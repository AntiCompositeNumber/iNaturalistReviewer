#!/usr/bin/env python3
# coding: utf-8
# SPDX-License-Identifier: Apache-2.0


# Copyright 2019 AntiCompositeNumber

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#   http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import urllib.parse
import hashlib
import argparse
import time
from hmac import compare_digest
from collections import namedtuple
from datetime import date
import pywikibot
import pywikibot.pagegenerators as pagegenerators
import mwparserfromhell as mwph
import requests

__version__ = "0.1.0"

logging.basicConfig(level=logging.INFO)
# Quiet pywikibot's overly-verbose logging
pywlog = logging.getLogger("pywiki")
pywlog.setLevel("INFO")

site = pywikibot.Site("commons", "commons")
iNaturalistID = namedtuple("iNaturalistID", "id type")
username = "iNaturalistReviewBot"
_session = None


def create_session():
    """Handles the creation of a Requests session with a descriptive UA

    If there is already a session, returns that session.
    Otherwise, a new session is created and returned
    """
    global _session

    if _session:
        return _session

    _session = requests.Session()
    _session.headers.update(
        {
            "user-agent": f"Bot iNaturalistReviewer/{__version__} "
            "on Wikimedia Toolforge "
            f"(Contact: https://commons.wikimedia.org/wiki/User:{username}; "
            "https://www.inaturalist.org/people/anticompositenumber "
            "tools.inaturalistreviewer@tools.wmflabs.org) "
            f"Python requests/{requests.__version__}"
        }
    )
    return _session


def check_runpage(override=False):
    """Checks the Commons runpage to determine if the bot can run.

    If the runpage does not end with True, an exception is raised.
    This check can be ignored by setting override to True
    """
    if not override:
        page = pywikibot.Page(site, "User:INaturalistReviewBot/Run")
        runpage = page.text.endswith("True")
        if not runpage:
            raise pywikibot.UserBlocked("Runpage is false, quitting...")
    else:
        logging.warning("Ignoring runpage setting!")


def files_to_check():
    """Iterate list of files needing review from Commons"""
    category = pywikibot.Category(site, "Category:INaturalist review needed")
    for page in pagegenerators.CategorizedPageGenerator(
        category, namespaces=6, site=site,
    ):
        yield page


def find_ina_id(page):
    """Returns an iNaturalistID tuple from wikitext"""
    for url in page.extlinks():
        url_id = parse_ina_url(url)
        if url_id is None:
            continue
        elif url_id.type == "observations":
            return url_id
    else:
        return None


def parse_ina_url(raw_url):
    """Parses an iNaturalist URL into an iNaturalistID named tuple"""
    url = urllib.parse.urlparse(raw_url)
    path = url.path.split(sep="/")
    if len(path) == 3 and "www.inaturalist.org" in url.netloc:
        return iNaturalistID(type=path[1], id=str(path[2]))
    else:
        return None


def get_ina_data(ina_id):
    """Make API request to iNaturalist from an ID and ID type

    Returns a dict of the API result
    """
    session = create_session()
    if ina_id.type == "observations":
        url = f"https://api.inaturalist.org/v1/observations/{ina_id.id}"
    else:
        return None

    try:
        response = session.get(url, headers={"Accept": "application/json"})
        response.raise_for_status()
        response_json = response.json()
    except (ValueError, requests.exceptions.HTTPError):
        return None
    else:
        if response_json.get("total_results") != 1:
            return None
        return response_json["results"][0]


def find_photo_in_obs(page, obs_id, ina_data):
    """Find the matching image in an iNaturalist observation

    Returns an iNaturalistID named tuple with the photo ID.
    """
    photos = [photo["id"] for photo in ina_data["photos"]]
    if len(photos) < 1:
        return None, "notfound"
    for photo_id in photos:
        photo = iNaturalistID(type="photos", id=str(photo_id))
        if compare_photo_hashes(page, photo):
            return photo, None
    else:
        return None, "notmatching"


def compare_photo_hashes(page, photo):
    """Compares the photo on iNaturalist to the hash of the Commons file"""
    session = create_session()
    url = f"https://static.inaturalist.org/photos/{photo.id}/original.jpeg"
    response = session.get(url)
    sha1sum = hashlib.sha1()
    sha1sum.update(response.content)
    com_hash = page.latest_file_info.sha1
    return compare_digest(com_hash, sha1sum.hexdigest())


def find_ina_license(ina_data, photo):
    """Find the image license in the iNaturalist API response

    If a license is found, the Commons template name is returned.
    If no license is found, an empty string is returned.

    The API does not return CC version numbers, but the website has 4.0 links.
    CC 4.0 licenses are assumed.
    """
    licenses = {
        "cc0": "Cc-zero",
        "cc-by": "Cc-by-4.0",
        "cc-by-nc": "Cc-by-nc-4.0",
        "cc-by-nd": "Cc-by-nd-4.0",
        "cc-by-sa": "Cc-by-sa-4.0",
        "cc-by-nc-nd": "Cc-by-nc-nd-4.0",
        "cc-by-nc-sa": "Cc-by-nc-sa-4.0",
        "null": "arr",
    }
    photos = ina_data.get("photos")
    for photo_data in photos:
        if str(photo_data.get("id")) == photo.id:
            license_code = photo_data.get("license_code")
            break
    else:
        return None

    return licenses.get(license_code)


def find_ina_author(ina_data):
    """Find the image author in the iNaturalist API response

    Returns a string with the username of the iNaturalist contributor
    """
    return ina_data.get("user", {}).get("login")


def find_com_license(page):
    """Find the license template currently used on the Commons page

    Returns the first license template used on the page. If no templates
    are found, return None
    """
    category = pywikibot.Category(site, "Category:Primary license tags (flat list)")

    for template in page.itertemplates():
        if template in category.members(namespaces=10):
            return template.title(with_ns=False)
    else:
        return None


def check_licenses(ina_license, com_license):
    """Checks the Commons license against the iNaturalist license

    Returns a string with the status
    Statuses:
        fail:       iNaturalist license is non-free
        error:      Bot could not determine
        pass:       Licenses match
        pass-change: Commons license changed to free iNaturalist license
    """
    free_licenses = {"Cc-zero", "Cc-by-4.0", "Cc-by-sa-4.0"}

    if not ina_license:
        # iNaturalist license wasn't found, call in the humans
        return "error"
    elif ina_license not in free_licenses:
        # Source license is non-free, failed license review
        return "fail"
    elif ina_license == com_license:
        # Licenses are the same, license review passes
        return "pass"
    else:
        # Commons license doesn't match iNaturalist, update to match
        return "pass-change"


def update_review(
    page,
    photo_id=None,
    status="error",
    author="",
    review_license="",
    upload_license="",
):
    """Updates the wikitext with the review status"""
    code = mwph.parse(page.text)
    template = make_template(
        photo_id=photo_id,
        status=status,
        author=author,
        review_license=review_license,
        upload_license=upload_license,
    )

    for pagetemplate in code.ifilter_templates(matches="iNaturalistreview"):
        for pt2 in code.ifilter_templates(matches=upload_license):
            # Remove existing license template
            if pt2.name.matches(upload_license):
                code.remove(pt2)
        code.replace(pagetemplate, template)
        if status == "fail":
            code.insert(
                0,
                "{{copyvio|Bot license review NOT PASSED: "
                f"iNaturalist author is using {review_license}}}}}",
            )
        break
    else:
        return False

    save_page(page, str(code), status, review_license)
    return True


def make_template(
    photo_id=None, status="", author="", review_license="", upload_license="",
):
    """Constructs the iNaturalistReview template"""
    text = f"{{{{iNaturalistReview }}}}"
    code = mwph.parse(text)
    template = code.get(0)
    template.add("status", status + " ", preserve_spacing=False)
    template.add("reviewdate", date.today().isoformat() + " ", preserve_spacing=False)
    template.add("reviewer", username + " ", preserve_spacing=False)

    if status != "error":
        code.insert(0, f"{{{{{review_license}}}}}")
        template.add(
            "author", author + " ", before="reviewdate", preserve_spacing=False
        )
        template.add(
            "sourceurl",
            f"https://www.inaturalist.org/photo/{photo_id.id} ",
            before="reviewdate",
            preserve_spacing=False,
        )

        if status == "pass-change":
            template.add("reviewlicense", review_license + " ", preserve_spacing=False)
            template.add(
                "uploadlicense", upload_license, preserve_spacing=False,
            )
        else:
            template.add("reviewlicense", review_license, preserve_spacing=False)

    return code


def save_page(page, new_text, status, review_license):
    """Replaces the wikitext of the specified page with new_text

    If the global simulate variable is true, the wikitext will be printed
    instead of saved to Commons.
    """
    summary = f"License review: {status} {review_license} (inrbot {__version__}"
    page.text = new_text
    simulate = True  # FIXME DEV ONLY
    if not simulate:
        logging.info(f"Saving {page.title()}")
        page.save(summary=summary)
    else:
        logging.info(f"Saving disabled")
        logging.info(summary)
        logging.info(page.text)


def review_file(inpage):
    """Performs a license review on the input page

    inpage must be in the file namespace.

    Returns None if the file was skipped
    Returns False if there was an error during review
    Returns True if the file was successfully reviewed (pass or fail)
    """
    try:
        page = pywikibot.FilePage(inpage)
    except ValueError:
        return None

    check_runpage(run_override)
    logging.info(f"Checking {page.title()}")
    wikitext_id = find_ina_id(page)
    logging.info(f"ID found in wikitext: {wikitext_id}")
    if wikitext_id.type != "observations":
        logging.info("Not a supported endpoint.")
        update_review(page, status="error")
        return False

    ina_data = get_ina_data(wikitext_id)

    photo_id, found = find_photo_in_obs(page, wikitext_id, ina_data)
    if found:
        logging.info(f"Images did not match: {found}")
        update_review(page, status="error")
        return False

    ina_license = find_ina_license(ina_data, photo_id)
    logging.info(f"iNaturalist License: {ina_license}")
    ina_author = find_ina_author(ina_data)
    logging.info(f"Author: {ina_author}")

    com_license = find_com_license(page)
    logging.info(f"Commons License: {com_license}")
    status = check_licenses(ina_license, com_license)
    logging.info(f"Status: {status}")
    update_review(
        page,
        photo_id,
        status=status,
        author=ina_author,
        review_license=ina_license,
        upload_license=com_license,
    )
    return True


def main(page=None, total=1):
    total = total - 1
    if page:
        review_file(page)
    else:
        i = 0
        while (not total) or (i < total):
            for i, page in enumerate(files_to_check()):
                review_file(page)
                time.sleep(60)
            else:
                logging.warning("Out of pages to check!")
                time.sleep(300)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Review files from iNaturalist on Commons",
        prog="iNaturalistReviewer",
    )
    run_method = parser.add_mutually_exclusive_group(required=True)
    run_method.add_argument(
        "--auto", action="store_true", help="run the bot automatically"
    )
    run_method.add_argument(
        "--file", action="store", help="run the bot only on the specified file"
    )
    parser.add_argument(
        "--total",
        action="store",
        help="review no more than this number of files in automatic mode",
        default=0,
    )
    parser.add_argument(
        "--ignore-runpage",
        action="store_true",
        dest="ignore_runpage",
        help="skip the runpage check for testing",
    )
    sim = parser.add_mutually_exclusive_group()
    sim.add_argument(
        "--simulate",
        action="store_true",
        help="print the output wikitext instead of saving to Commons",
    )
    sim.add_argument(
        "--no-simulate",
        action="store_true",
        dest="no_simulate",
        help="forces saving when disabled by --ignore-runpage",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s " + __version__
    )
    args = parser.parse_args()

    run_override = args.ignore_runpage
    if run_override:
        if args.no_simulate:
            simulate = False
        else:
            simulate = True
    else:
        simulate = args.simulate

    if args.auto:
        main(total=args.total)
    elif args.file and "File" in args.file:
        main(page=pywikibot.Page(site, args.file))
else:
    run_override = False
    simulate = False

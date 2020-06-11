#!/usr/bin/env python3
# coding: utf-8
# SPDX-License-Identifier: Apache-2.0


# Copyright 2020 AntiCompositeNumber

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
import logging.config
import urllib.parse
import hashlib
import argparse
import time
from datetime import date
from hmac import compare_digest
import pywikibot  # type: ignore
import pywikibot.pagegenerators as pagegenerators  # type: ignore
import mwparserfromhell as mwph  # type: ignore
import requests
import utils

from typing import Optional, Tuple, NamedTuple, Set, Union

__version__ = "0.3.0"
username = "iNaturalistReviewBot"

logging.config.dictConfig(
    utils.logger_config("inrbot", level="VERBOSE", filename="inrbot.log")
)
logger = logging.getLogger("inrbot")

site = pywikibot.Site("commons", "commons")
iNaturalistID = NamedTuple("iNaturalistID", [("id", str), ("type", str)])
skip: Set[str] = set()


session = requests.Session()
session.headers.update(
    {
        "user-agent": f"Bot iNaturalistReviewer/{__version__} "
        "on Wikimedia Toolforge "
        f"(Contact: https://commons.wikimedia.org/wiki/User:{username}; "
        "https://www.inaturalist.org/people/anticompositenumber "
        "tools.inaturalistreviewer@tools.wmflabs.org) "
        f"Python requests/{requests.__version__}"
    }
)


def check_can_run(page: pywikibot.page.BasePage) -> bool:
    """Determinies if the bot should run on this page and returns a bool."""

    if (
        (page.title() in skip)
        or (not page.has_permission("edit"))
        or (not page.botMayEdit())
        or ("{{iNaturalistreview}}" not in page.text)
    ):
        return False
    else:
        return True


def files_to_check() -> pywikibot.page.BasePage:
    """Iterate list of files needing review from Commons"""
    category = pywikibot.Category(site, "Category:INaturalist review needed")
    for page in pagegenerators.CategorizedPageGenerator(category, namespaces=6):
        yield page


def find_ina_id(page: pywikibot.page.BasePage) -> Optional[iNaturalistID]:
    """Returns an iNaturalistID tuple from wikitext"""
    for url in page.extlinks():
        url_id = parse_ina_url(url)
        if url_id is None:
            continue
        elif url_id.type == "observations":
            return url_id
    else:
        return None


def parse_ina_url(raw_url: str) -> Optional[iNaturalistID]:
    """Parses an iNaturalist URL into an iNaturalistID named tuple"""
    url = urllib.parse.urlparse(raw_url)
    path = url.path.split(sep="/")
    if len(path) == 3 and "www.inaturalist.org" in url.netloc:
        return iNaturalistID(type=path[1], id=str(path[2]))
    else:
        return None


def get_ina_data(ina_id: iNaturalistID) -> Optional[dict]:
    """Make API request to iNaturalist from an ID and ID type

    Returns a dict of the API result
    """
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
        return response_json.get("results", [None])[0]


def find_photo_in_obs(
    page: pywikibot.FilePage, obs_id: iNaturalistID, ina_data: dict
) -> Union[Tuple[iNaturalistID, None], Tuple[None, str]]:
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


def compare_photo_hashes(page: pywikibot.FilePage, photo: iNaturalistID) -> bool:
    """Compares the photo on iNaturalist to the hash of the Commons file"""
    url = f"https://static.inaturalist.org/photos/{photo.id}/original.jpeg"
    response = session.get(url)
    sha1sum = hashlib.sha1()
    sha1sum.update(response.content)
    com_hash = page.latest_file_info.sha1
    return compare_digest(com_hash, sha1sum.hexdigest())


def find_ina_license(ina_data: dict, photo: iNaturalistID) -> str:
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
    photos: list = ina_data.get("photos", [])
    for photo_data in photos:
        if str(photo_data.get("id")) == photo.id:
            license_code = photo_data.get("license_code")
            break
    else:
        return ""

    return licenses.get(license_code, "")


def find_ina_author(ina_data: dict) -> str:
    """Find the image author in the iNaturalist API response

    Returns a string with the username of the iNaturalist contributor
    """
    return ina_data.get("user", {}).get("login", "")


def find_com_license(page: pywikibot.page.BasePage) -> str:
    """Find the license template currently used on the Commons page

    Returns the first license template used on the page. If no templates
    are found, return an empty string.
    """
    category = pywikibot.Category(site, "Category:Primary license tags (flat list)")

    for template in page.itertemplates():
        if template in category.members(namespaces=10):
            return template.title(with_ns=False)
    else:
        return ""


def check_licenses(ina_license: str, com_license: str) -> str:
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
    page: pywikibot.page.BasePage,
    photo_id: Optional[iNaturalistID] = None,
    status: str = "error",
    author: str = "",
    review_license: str = "",
    upload_license: str = "",
) -> bool:
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
    photo_id: Optional[iNaturalistID] = None,
    status: str = "",
    author: str = "",
    review_license: str = "",
    upload_license: str = "",
) -> mwph.wikicode.Wikicode:
    """Constructs the iNaturalistReview template"""
    text = "{{iNaturalistReview }}"
    code = mwph.parse(text)
    template = code.get(0)
    template.add("status", status + " ", preserve_spacing=False)
    template.add("reviewdate", date.today().isoformat() + " ", preserve_spacing=False)
    template.add("reviewer", username + " ", preserve_spacing=False)

    if status != "error":
        assert isinstance(photo_id, iNaturalistID)
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


def save_page(
    page: pywikibot.page.BasePage, new_text: str, status: str, review_license: str
) -> None:
    """Replaces the wikitext of the specified page with new_text

    If the global simulate variable is true, the wikitext will be printed
    instead of saved to Commons.
    """
    summary = f"License review: {status} {review_license} (inrbot {__version__}"
    if not simulate:
        utils.check_runpage(site, run_override)
        logger.info(f"Saving {page.title()}")
        utils.save_page(
            text=new_text, page=page, summary=summary, bot=False, minor=False
        )
    else:
        logger.info("Saving disabled")
        logger.info(summary)
        logger.info(new_text)


def review_file(inpage: pywikibot.page.BasePage) -> Optional[bool]:
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

    utils.check_runpage(site, run_override)
    if not check_can_run(page):
        return None

    logger.info(f"Checking {page.title()}")

    wikitext_id = find_ina_id(page)
    logger.info(f"ID found in wikitext: {wikitext_id}")
    if wikitext_id is None:
        return None
    elif wikitext_id.type != "observations":
        logger.info("Not a supported endpoint.")
        update_review(page, status="error")
        return False

    ina_data = get_ina_data(wikitext_id)

    if not ina_data:
        logger.warning("No data retrieved from iNaturalist!")
        update_review(page, status="error")
        return False

    photo_id, found = find_photo_in_obs(page, wikitext_id, ina_data)
    if found:
        logger.info(f"Images did not match: {found}")
        update_review(page, status="error")
        return False
    else:
        assert isinstance(photo_id, iNaturalistID)

    ina_license = find_ina_license(ina_data, photo_id)
    logger.debug(f"iNaturalist License: {ina_license}")
    ina_author = find_ina_author(ina_data)
    logger.debug(f"Author: {ina_author}")

    com_license = find_com_license(page)
    logger.debug(f"Commons License: {com_license}")
    status = check_licenses(ina_license, com_license)
    logger.debug(f"Status: {status}")
    update_review(
        page,
        photo_id,
        status=status,
        author=ina_author,
        review_license=ina_license,
        upload_license=com_license,
    )
    return True


def main(page: Optional[pywikibot.page.BasePage] = None, total: int = 0) -> None:
    """Main loop for program"""
    # Enumerate starts at 0, so to get N items, count to N-1.
    if page:
        # When given a page, check only that page
        review_file(page)
    else:
        # Otherwise, run automatically
        # If total is 0, run continuously.
        # If total is non-zero, check that many files
        i = 0
        running = True
        while (not total) or (i < total):
            for page in files_to_check():
                if total and i >= total:
                    break
                else:
                    i += 1

                try:
                    review_file(page)
                except pywikibot.UserBlocked as err:
                    # Blocks and runpage checks always stop
                    logger.exception(err)
                    raise
                except Exception as err:
                    if running:
                        logger.exception(err)
                        running = False
                    else:
                        # If this exception happened after running out
                        # of pages or another exception, stop the bot.
                        logger.exception(err)
                        raise

                time.sleep(60)
                running = True
            else:
                # If the for loop drops out, there are no more pages right now
                if running:
                    running = False
                    logger.warning("Out of pages to check!")
                # May need to adjust this number depending on load
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

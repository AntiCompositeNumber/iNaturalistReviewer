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

import argparse
import hashlib
import json
import logging
import logging.config
import string
import time
import urllib.parse
from datetime import date
from hmac import compare_digest
from io import BytesIO

import mwparserfromhell as mwph  # type: ignore
import pywikibot  # type: ignore
import pywikibot.pagegenerators as pagegenerators  # type: ignore
import requests
from PIL import Image  # type: ignore
import ssim as pyssim  # type: ignore

from typing import NamedTuple, Optional, Set, Tuple, Dict, Union

import utils

__version__ = "0.5.0"
username = "iNaturalistReviewBot"

logging.config.dictConfig(
    utils.logger_config("inrbot", level="VERBOSE", filename="inrbot.log")
)
logger = logging.getLogger("inrbot")

site = pywikibot.Site("commons", "commons")
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


class iNaturalistID(NamedTuple):
    id: str
    type: str
    url: str = ""

    def __str__(self):
        return f"https://www.inaturalist.org/{self.type}/{self.id}"


def get_config():
    """Load on-wiki configuration"""
    page = pywikibot.Page(site, "User:iNaturalistReviewBot/config.json")
    conf_json = json.loads(page.text)
    logger.info(f"Loaded config from {page.title(as_link=True)}")
    logger.debug(conf_json)
    return conf_json


def check_can_run(page: pywikibot.page.BasePage) -> bool:
    """Determinies if the bot should run on this page and returns a bool."""

    if (
        (page.title() in skip)
        or (not page.has_permission("edit"))
        or (not page.botMayEdit())
        or (
            pywikibot.Page(site, "Template:iNaturalistreview")
            not in set(page.itertemplates())
        )
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


def get_ina_data(
    ina_id: iNaturalistID, throttle: Optional[utils.Throttle] = None
) -> Optional[dict]:
    """Make API request to iNaturalist from an ID and ID type

    Returns a dict of the API result
    """
    if ina_id.type == "observations":
        url = f"https://api.inaturalist.org/v1/observations/{ina_id.id}"
    else:
        return None

    if throttle:
        throttle.throttle()
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
    page: pywikibot.FilePage,
    obs_id: iNaturalistID,
    ina_data: dict,
    throttle: Optional[utils.Throttle] = None,
) -> Tuple[Optional[iNaturalistID], str]:
    """Find the matching image in an iNaturalist observation

    Returns an iNaturalistID named tuple with the photo ID.
    """
    photos = [
        iNaturalistID(type="photos", id=str(photo["id"]), url=photo["url"])
        for photo in ina_data["photos"]
    ]
    if len(photos) < 1:
        return None, "notfound"

    logger.debug("Checking sha1 hashes")
    for photo in photos:
        logger.debug(f"Current photo: {photo}")
        if compare_photo_hashes(page, photo):
            return photo, "sha1"
        if throttle:
            throttle.throttle()

    if config["use_ssim"]:
        # Hash check failed, use SSIM instead
        logger.debug("Hash check failed, checking SSIM scores")
        try:
            orig = get_commons_image(page)
        except Exception:
            pass
        else:
            for photo in photos:
                logger.debug(f"Current photo: {photo}")
                res, ssim = compare_ssim(orig, photo)
                if res:
                    return photo, f"ssim: {ssim}"
                if throttle:
                    throttle.throttle()

    return None, "notmatching"


def compare_photo_hashes(page: pywikibot.FilePage, photo: iNaturalistID) -> bool:
    """Compares the photo on iNaturalist to the hash of the Commons file"""
    sha1sum = hashlib.sha1()
    try:
        image = utils.retry(get_ina_image, 3, photo=photo)
    except Exception as err:
        logger.exception(err)
        return False
    sha1sum.update(image)
    com_hash = page.latest_file_info.sha1
    ina_hash = sha1sum.hexdigest()
    logger.debug(f"Commons sha1sum:     {com_hash}")
    logger.debug(f"iNaturalist sha1sum: {ina_hash}")
    return compare_digest(com_hash, ina_hash)


def get_ina_image(photo: iNaturalistID, final: bool = False) -> bytes:
    """Download original photo from iNaturalist"""
    if photo.url:
        extension = photo.url.rpartition("?")[0].rpartition(".")[2]
    else:
        extension == "jpeg"
    url = f"https://static.inaturalist.org/photos/{photo.id}/original.{extension}"
    response = session.get(url)
    if response.status_code == 403 and not final:
        return get_ina_image(photo._replace(url=url.replace("jpeg", "jpg")), final=True)
    response.raise_for_status()
    return response.content


def get_commons_image(page: pywikibot.FilePage) -> Image.Image:
    """Download orignal Commons file and open as a PIL image"""
    url = page.get_file_url()
    response = session.get(url)
    response.raise_for_status()
    return Image.open(BytesIO(response.content))


def compare_ssim(
    orig: Image, photo: iNaturalistID, min_ssim: float = 0.0
) -> Tuple[bool, float]:
    """Compares an iNaturalist photo to the Commons file using an SSIM score"""
    if not min_ssim:
        min_ssim = config.get("min_ssim", 0.9)
    assert min_ssim > 0 and min_ssim < 1
    try:
        image = utils.retry(get_ina_image, 3, photo=photo)
    except Exception as err:
        logger.exception(err)
        return False, 0.0
    ina_image = Image.open(BytesIO(image))

    ssim = pyssim.compute_ssim(orig, ina_image)
    logger.debug(f"SSIM value: {ssim}")
    return (ssim > min_ssim, ssim)


def find_ina_license(ina_data: dict, photo: iNaturalistID) -> str:
    """Find the image license in the iNaturalist API response

    If a license is found, the Commons template name is returned.
    If no license is found, an empty string is returned.

    The API does not return CC version numbers, but the website has 4.0 links.
    CC 4.0 licenses are assumed.
    """
    licenses = config["ina_licenses"]
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
    free_licenses = set(config["free_licenses"])

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


class Aliases:
    alias_cache: Dict[str, Dict[str, Union[float, Set[str]]]] = {}

    def __init__(self, title: str) -> None:
        self.title: str = title
        self._aliases: Optional[Set[str]] = None

    def get_aliases(self) -> None:
        canon_page = pywikibot.Page(site, f"Template:{self.title}")
        aliases = {
            page.title(with_ns=False).lower()
            for page in canon_page.backlinks(filter_redirects=True, namespaces=10)
        }
        aliases.add(canon_page.title(with_ns=False).lower())
        aliases.update(
            page.title(with_ns=False).lower().partition("/")[0]
            for page in canon_page.embeddedin(namespaces=10)
        )
        self._aliases = aliases

    @property
    def aliases(self):
        if self._aliases is None:
            cached = self.alias_cache.get(self.title)
            if cached is None or time.monotonic() - cached["last_update"] > 3600:
                self.get_aliases()
                self.alias_cache[self.title] = {
                    "last_update": time.monotonic(),
                    "aliases": self._aliases,
                }
            else:
                self._aliases = cached["aliases"]
        return self._aliases

    def is_license(self, template: mwph.nodes.Template) -> bool:
        if template.name.lower() in self.aliases:
            return True
        elif template.name.lower() == "self":
            return True
        return False


def update_review(
    page: pywikibot.page.BasePage,
    photo_id: Optional[iNaturalistID] = None,
    status: str = "error",
    author: str = "",
    review_license: str = "",
    upload_license: str = "",
    reason: str = "",
) -> bool:
    """Updates the wikitext with the review status"""
    code = mwph.parse(page.text)
    template = make_template(
        photo_id=photo_id,
        status=status,
        author=author,
        review_license=review_license,
        upload_license=upload_license,
        reason=reason,
    )
    for review_template in code.ifilter_templates(
        matches=lambda t: t.name.lower() == "inaturalistreview"
    ):
        code.replace(review_template, template)
    if status == "pass-change":
        aliases = Aliases(upload_license)
        for pt2 in code.ifilter_templates(matches=aliases.is_license):
            code.replace(pt2, ("{{%s}}" % review_license))
    if status == "fail":
        code.insert(
            0,
            string.Template(config["fail_tag"]).safe_substitute(
                review_license=review_license
            ),
        )

    try:
        save_page(page, str(code), status, review_license)
    except Exception as err:
        logging.exception(err)
        return False
    else:
        return True


def make_template(
    photo_id: Optional[iNaturalistID] = None,
    status: str = "",
    author: str = "",
    review_license: str = "",
    upload_license: str = "",
    reason: str = "",
) -> str:
    """Constructs the iNaturalistReview template"""
    template = string.Template(config[status])
    text = template.safe_substitute(
        status=status,
        author=author,
        source_url=str(photo_id),
        review_date=date.today().isoformat(),
        reviewer=username,
        review_license=review_license,
        upload_license=upload_license,
        reason=reason,
    )
    return text


def save_page(
    page: pywikibot.page.BasePage, new_text: str, status: str, review_license: str
) -> None:
    """Replaces the wikitext of the specified page with new_text

    If the global simulate variable is true, the wikitext will be printed
    instead of saved to Commons.
    """
    summary = string.Template(config["review_summary"]).safe_substitute(
        status=status, review_license=review_license, version=__version__
    )
    if not simulate:
        utils.check_runpage(site, run_override)
        logger.info(f"Saving {page.title()}")
        utils.retry(
            utils.save_page,
            3,
            text=new_text,
            page=page,
            summary=summary,
            bot=False,
            minor=False,
        )
    else:
        logger.info("Saving disabled")
        logger.info(summary)
        logger.info(new_text)


def get_author_talk(page: pywikibot.page.FilePage) -> pywikibot.page.Page:
    return pywikibot.Page(site, f"User talk:{page.oldest_file_info.user}")


def fail_warning(page: pywikibot.page.BasePage, review_license: str) -> None:
    user_talk = get_author_talk(page)
    message = string.Template(config["fail_warn"]).safe_substitute(
        filename=page.title(with_ns=True), review_license=review_license
    )
    summary = string.Template(config["review_summary"]).safe_substitute(
        status="fail", review_license=review_license, version=__version__
    )
    if not simulate:
        utils.check_runpage(site, run_override)
        logger.info(f"Saving {page.title()}")
        utils.retry(
            utils.save_page,
            3,
            text=message,
            page=user_talk,
            summary=summary,
            bot=False,
            minor=False,
            mode="append",
        )
    else:
        logger.info("Saving disabled")
        logger.info(summary)
        logger.info(message)


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
    logger.info(f"Checking {page.title()}")

    utils.check_runpage(site, run_override)
    if not check_can_run(page):
        return None

    wikitext_id = find_ina_id(page)
    logger.info(f"ID found in wikitext: {wikitext_id}")
    if wikitext_id is None:
        return None
    elif wikitext_id.type != "observations":
        logger.info("Not a supported endpoint.")
        update_review(page, status="error", reason="photos")
        return False

    ina_throttle = utils.Throttle(10)
    ina_data = get_ina_data(wikitext_id, ina_throttle)

    if not ina_data:
        logger.warning("No data retrieved from iNaturalist!")
        update_review(page, status="error", reason="nodata")
        return False

    photo_id, found = find_photo_in_obs(page, wikitext_id, ina_data, ina_throttle)
    if photo_id is None:
        logger.info(f"Images did not match: {found}")
        update_review(page, status="error", reason=found)
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
    reviewed = update_review(
        page,
        photo_id,
        status=status,
        author=ina_author,
        review_license=ina_license,
        upload_license=com_license,
        reason=found,
    )
    if status == "fail" and reviewed:
        fail_warning(page, ina_license)

    return reviewed


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
        logger.info("Beginning loop")
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


config = get_config()
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

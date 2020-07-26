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
import datetime
import hashlib
import json
import logging
import logging.config
import re
import string
import time
import urllib.parse
from hmac import compare_digest
from io import BytesIO

import imagehash  # type: ignore
import mwparserfromhell as mwph  # type: ignore
import pywikibot  # type: ignore
import pywikibot.pagegenerators as pagegenerators  # type: ignore
import requests
import PIL.Image  # type: ignore
import waybackpy  # type: ignore

from typing import NamedTuple, Optional, Set, Tuple, Dict, Union, cast

import utils

__version__ = "1.2.0"
username = "iNaturalistReviewBot"

logging.config.dictConfig(
    utils.logger_config("inrbot", level="VERBOSE", filename="inrbot.log")
)
logger = logging.getLogger("inrbot")

site = pywikibot.Site("commons", "commons")
skip: Set[str] = set()
user_agent = (
    f"Bot iNaturalistReviewer/{__version__} "
    "on Wikimedia Toolforge "
    f"(Contact: https://commons.wikimedia.org/wiki/User:{username}; "
    "https://www.inaturalist.org/people/anticompositenumber "
    "tools.inaturalistreviewer@tools.wmflabs.org) "
    f"Python requests/{requests.__version__}"
)

session = requests.Session()
session.headers.update({"user-agent": user_agent})
recent_bytes = {}
conf_ts = None


class iNaturalistID(NamedTuple):
    id: str
    type: str
    url: str = ""

    def __str__(self):
        return f"https://www.inaturalist.org/{self.type}/{self.id}"

    def __eq__(self, other):
        if isinstance(other, iNaturalistID):
            return self.id == other.id and self.type == other.type
        else:
            return NotImplemented


class RestartBot(RuntimeError):
    pass


class ProcessingError(Exception):
    def __init__(self, reason_code, description=""):
        self.reason_code = reason_code
        self.description = description


def get_config() -> Tuple[dict, datetime.datetime]:
    """Load on-wiki configuration"""
    page = pywikibot.Page(site, "User:iNaturalistReviewBot/config.json")
    conf_json = json.loads(page.text)
    logger.info(f"Loaded config from {page.title(as_link=True)}")
    logger.debug(json.dumps(conf_json, indent=2))
    ts = datetime.datetime.utcnow()
    return conf_json, ts


def check_config():
    page = pywikibot.Page(site, "User:iNaturalistReviewBot/config.json")
    if conf_ts and page.editTime() > conf_ts:
        raise RestartBot("Configuration has been updated, bot will restart")


def check_can_run(page: pywikibot.page.BasePage) -> bool:
    """Determinies if the bot should run on this page and returns a bool."""

    if (
        (page.title() in skip)
        or (not page.has_permission("edit"))
        or (not page.botMayEdit())
        or (not re.search("{{[iI][nN]aturalist[rR]eview}}", page.text))
    ):
        return False
    else:
        return True


def files_to_check(start: Optional[str] = None) -> pywikibot.page.BasePage:
    """Iterate list of files needing review from Commons"""
    category = pywikibot.Category(site, "Category:INaturalist review needed")
    for page in pagegenerators.CategorizedPageGenerator(
        category, namespaces=6, start=start
    ):
        yield page


def find_ina_id(
    page: pywikibot.page.BasePage,
) -> Tuple[Optional[iNaturalistID], Optional[iNaturalistID]]:
    """Returns an iNaturalistID tuple from wikitext"""
    photos = set()
    observations = set()
    for url in page.extlinks():
        url_id = parse_ina_url(url)
        if url_id is None or re.search(r"[A-z]", url_id.id):
            continue
        elif url_id.type == "observations":
            observations.add(url_id)
        elif url_id.type == "photos":
            photos.add(url_id)

    if photos and observations:
        return observations.pop(), photos.pop()
    elif observations:
        return observations.pop(), None
    elif photos:
        return None, photos.pop()
    else:
        raise ProcessingError("nourl", "No observation ID could be found")


def parse_ina_url(raw_url: str) -> Optional[iNaturalistID]:
    """Parses an iNaturalist URL into an iNaturalistID named tuple"""
    url = urllib.parse.urlparse(raw_url)
    path = url.path.split(sep="/")
    netloc = url.netloc.lower()
    if len(path) == 3 and any(
        netloc.endswith(domain)
        for domain in (
            "inaturalist.org",
            "naturalista.mx",
            "argentinat.org",
            "inaturalist.ala.org.au",
            "biodiversity4all.org",
            "inaturalist.ca",
            "inaturalist.nz",
            "inaturalist.laji.fi",
        )
    ):
        return iNaturalistID(type=path[1], id=str(path[2]))
    elif len(path) == 4 and netloc == "static.inaturalist.org":
        return iNaturalistID(type=path[1], id=str(path[2]))
    else:
        return None


def get_ina_data(
    ina_id: iNaturalistID, throttle: Optional[utils.Throttle] = None
) -> dict:
    """Make API request to iNaturalist from an ID and ID type

    Returns a dict of the API result
    """
    if ina_id.type == "observations":
        url = f"https://api.inaturalist.org/v1/observations/{ina_id.id}"
    else:
        raise ProcessingError("apierr", "iNaturalist ID is wrong type")

    if throttle:
        throttle.throttle()
    try:
        response = session.get(url, headers={"Accept": "application/json"})
        response.raise_for_status()
        response_json = response.json()
    except (ValueError, requests.exceptions.HTTPError) as err:
        raise ProcessingError("apierr", "iNaturalist API error") from err
    else:
        if response_json.get("total_results") != 1:
            raise ProcessingError("apierr", "iNaturalist API error")
        res = response_json.get("results", [None])[0]
        if not res:
            raise ProcessingError("apierr", "No data recieved from iNaturalist")
        return res


class Image:
    def __init__(
        self,
        raw: Optional[bytes] = None,
        image: Optional[PIL.Image.Image] = None,
        sha1: str = "",
        phash: Optional[imagehash.ImageHash] = None,
    ):
        self._raw = raw
        self._image = image
        self._sha1 = sha1
        self._phash = phash

    @property
    def phash(self) -> imagehash.ImageHash:
        if not self._phash:
            self._phash = imagehash.phash(self.image)
        return self._phash

    @property
    def image(self):
        raise NotImplementedError


class iNaturalistImage(Image):
    def __init__(self, id: iNaturalistID, **kwargs):
        self.id = id
        super().__init__(**kwargs)

    @property
    def raw(self) -> bytes:
        if not self._raw:
            self._raw = utils.retry(get_ina_image, 3, photo=self.id)
        return cast(bytes, self._raw)

    @property
    def image(self) -> PIL.Image.Image:
        if not self._image:
            self._image = PIL.Image.open(BytesIO(self.raw))
        return self._image

    @property
    def sha1(self) -> str:
        if not self._sha1:
            sha1sum = hashlib.sha1()
            sha1sum.update(self.raw)
            self._sha1 = sha1sum.hexdigest()
        return self._sha1


class CommonsImage(Image):
    def __init__(self, page: pywikibot.FilePage, **kwargs):
        self.page = page
        super().__init__(**kwargs)

    @property
    def raw(self):
        return NotImplemented

    @property
    def image(self) -> PIL.Image.Image:
        """Download orignal Commons file and open as a PIL image"""
        if not self._image:
            url = self.page.get_file_url()
            response = session.get(url)
            response.raise_for_status()
            self._image = PIL.Image.open(BytesIO(response.content))
        return self._image

    @property
    def sha1(self) -> str:
        if not self._sha1:
            self._sha1 = self.page.latest_file_info.sha1
        return self._sha1


def find_photo_in_obs(
    page: pywikibot.FilePage,
    obs_id: iNaturalistID,
    ina_data: dict,
    raw_photo_id: Optional[iNaturalistID] = None,
    throttle: Optional[utils.Throttle] = None,
) -> Tuple[iNaturalistID, str]:
    """Find the matching image in an iNaturalist observation

    Returns an iNaturalistID named tuple with the photo ID.
    """
    images = [
        iNaturalistImage(
            id=iNaturalistID(type="photos", id=str(photo["id"]), url=photo["url"])
        )
        for photo in ina_data["photos"]
    ]
    if len(images) < 1:
        raise ProcessingError("notfound", "No photos in observation")
    elif raw_photo_id:
        filt_images = [image for image in images if image.id == raw_photo_id]
        if len(filt_images) > 0:
            images = filt_images

    commons_image = CommonsImage(page=page)

    for comp_method in config["compare_methods"]:
        logger.debug(f"Comparing photos using {comp_method}")
        for image in images:
            try:
                res = compare_images(comp_method, commons_image, image)
            except Exception:
                res = False
            if res:
                return image.id, comp_method

    raise ProcessingError("notmatching", "No matching photos found")


def compare_images(
    method: str, com_img: CommonsImage, ina_img: iNaturalistImage
) -> bool:
    """Compares a CommonsImage to an iNaturalistImage"""
    if method == "sha1":
        logger.debug(f"Commons sha1sum:     {com_img.sha1}")
        logger.debug(f"iNaturalist sha1sum: {ina_img.sha1}")
        return compare_digest(com_img.sha1, ina_img.sha1)

    elif method == "phash":
        diff = com_img.phash - ina_img.phash
        logger.debug(f"PHash Hamming distance: {diff}")
        return diff < 4
    else:
        raise ValueError


def get_ina_image(photo: iNaturalistID, final: bool = False) -> bytes:
    """Download original photo from iNaturalist"""
    if photo.url:
        extension = photo.url.partition("?")[0].rpartition(".")[2]
    else:
        extension == "jpeg"
    url = f"https://static.inaturalist.org/photos/{photo.id}/original.{extension}"
    response = session.get(url)
    if response.status_code == 403 and not final:
        return get_ina_image(photo._replace(url=url.replace("jpeg", "jpg")), final=True)
    response.raise_for_status()
    return response.content


def bytes_throttle(length: int) -> None:
    hour_limit = 4.5e9
    day_limit = 23.5e9
    global recent_bytes
    logger.debug(f"Content length: {length}")
    now = datetime.datetime.now()
    recent_bytes[datetime.datetime.now()] = length

    last_hour = 0
    last_day = 0
    for date, val in recent_bytes.copy().items():
        if now - date <= datetime.timedelta(hours=24):
            last_day += val
            if now - date <= datetime.timedelta(hours=1):
                last_hour += val
        else:
            del recent_bytes[date]

    logger.debug(f"Hour total: {last_hour}, day total: {last_day}")
    if last_day >= day_limit:
        logger.error(
            f"{last_day} bytes transferred in last 24h, approaching iNaturalist limits!"
        )
        sleep_time = 3600 * 12  # 12 hours
    elif last_hour >= hour_limit:
        logger.error(
            f"{last_hour} bytes transferred in last hour, "
            "approaching iNaturalist limits!"
        )
        sleep_time = 60 * 30  # 30 minutes
    else:
        return None
    logger.info(f"Sleeping for {sleep_time} seconds")
    time.sleep(sleep_time)
    return None


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
            license_code = photo_data.get("license_code", "null")
            break
    else:
        raise ProcessingError("inatlicense", "No iNaturalist license found")

    if not license_code:
        license_code = "null"

    try:
        return licenses[license_code]
    except KeyError as e:
        raise ProcessingError("inatlicense", "No iNaturalist license found") from e


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
        raise ProcessingError("comlicense", "No Commons license found")


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
    is_old: bool = False,
    throttle: Optional[utils.Throttle] = None,
    archive: str = "",
) -> bool:
    """Updates the wikitext with the review status"""
    logger.info(f"Status: {status} ({reason})")
    code = mwph.parse(page.text)
    template = make_template(
        photo_id=photo_id,
        status=status,
        author=author,
        review_license=review_license,
        upload_license=upload_license,
        reason=reason,
        archive=archive,
    )
    changed = False
    for review_template in code.ifilter_templates(
        matches=lambda t: t.name.lower() == "inaturalistreview"
    ):
        code.replace(review_template, template)
        changed = True
    if not changed:
        return False
    if status == "pass-change":
        aliases = Aliases(upload_license)
        for pt2 in code.ifilter_templates(matches=aliases.is_license):
            code.replace(pt2, ("{{%s}}" % review_license))
    if status == "fail":
        code.insert(
            0,
            string.Template(
                config["old_fail_tag"] if is_old else config["fail_tag"]
            ).safe_substitute(review_license=review_license),
        )
    if throttle is not None:
        throttle.throttle()

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
    archive: str = "",
) -> str:
    """Constructs the iNaturalistReview template"""
    template = string.Template(config[status])
    text = template.safe_substitute(
        status=status,
        author=author,
        source_url=str(photo_id),
        review_date=datetime.date.today().isoformat(),
        reviewer=username,
        review_license=review_license,
        upload_license=upload_license,
        reason=reason,
        archive=archive,
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
        logger.debug(summary)
        logger.debug(new_text)


def get_author_talk(page: pywikibot.page.FilePage) -> pywikibot.page.Page:
    return pywikibot.Page(site, f"User talk:{page.oldest_file_info.user}")


def fail_warning(
    page: pywikibot.page.BasePage, review_license: str, is_old: bool = False
) -> None:
    user_talk = get_author_talk(page)
    message = string.Template(
        config["old_fail_warn"] if is_old else config["fail_warn"]
    ).safe_substitute(filename=page.title(with_ns=True), review_license=review_license)
    summary = string.Template(config["review_summary"]).safe_substitute(
        status="fail", review_license=review_license, version=__version__
    )
    if not simulate:
        utils.check_runpage(site, run_override)
        logger.info(f"Saving {user_talk.title()}")
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


def get_observation_from_photo(photo_id: iNaturalistID) -> iNaturalistID:
    assert photo_id.type == "photos"
    try:
        res = session.get(str(photo_id))
        res.raise_for_status()
    except Exception:
        raise ProcessingError("nourl", "No observation ID could be found")
    # Yes, I know I'm parsing HTML with a regex.
    match = re.search(r"/observations/(\d*)\"", res.text)
    if not match:
        raise ProcessingError("nourl", "No observation ID could be found")
    else:
        return iNaturalistID(type="observations", id=match.group(1))


def file_is_old(page: pywikibot.page.FilePage) -> bool:
    if not config.get("old_fail", False):
        return False

    timestamp = page.latest_file_info.timestamp
    if (datetime.datetime.now() - timestamp) > datetime.timedelta(
        days=config["old_fail_age"]
    ):
        return True
    else:
        return False


def get_archive(photo_id: iNaturalistID) -> str:
    try:
        archive = waybackpy.Url(str(photo_id), user_agent).save()
    except Exception as err:
        logger.warn("Failed to get archive")
        logger.exception(err)
        archive = ""
    return archive


def get_old_archive(photo_id: iNaturalistID) -> str:
    try:
        archive = waybackpy.Url(str(photo_id), user_agent).oldest()
    except Exception as err:
        logger.warn("Failed to get archive", exc_info=err)
        archive = ""
    return archive


def review_file(
    inpage: pywikibot.page.BasePage, throttle: Optional[utils.Throttle] = None
) -> Optional[bool]:
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
    logger.info(f"Checking {page.title(as_link=True)}")

    utils.check_runpage(site, run_override)
    if not check_can_run(page):
        return None

    #####
    try:
        raw_obs_id, raw_photo_id = find_ina_id(page)
        logger.info(f"ID found in wikitext: {raw_obs_id} {raw_photo_id}")
        if raw_photo_id and not raw_obs_id:
            raw_obs_id = get_observation_from_photo(raw_photo_id)
        assert raw_obs_id

        ina_throttle = utils.Throttle(10)
        ina_data = get_ina_data(raw_obs_id, ina_throttle)

        photo_id, found = find_photo_in_obs(
            page, raw_obs_id, ina_data, raw_photo_id, ina_throttle
        )

        ina_license = find_ina_license(ina_data, photo_id)
        logger.debug(f"iNaturalist License: {ina_license}")
        ina_author = find_ina_author(ina_data)
        logger.debug(f"Author: {ina_author}")

        com_license = find_com_license(page)
        logger.debug(f"Commons License: {com_license}")
        status = check_licenses(ina_license, com_license)
        if status == "fail":
            is_old = file_is_old(page)
        else:
            is_old = False

        if config["use_wayback"] and status in ("pass", "pass-change"):
            archive = get_archive(photo_id)
        elif status == "fail":
            archive = get_old_archive(photo_id)
            if archive:
                status = "fail-archive"
        else:
            archive = ""

    except ProcessingError as err:
        logger.info("Processing failed:", exc_info=err)
        status = "error"
        kwargs = dict(status=status, reason=err.reason_code, throttle=throttle,)
    except Exception as err:
        logger.exception(err)
        status = "error"
        kwargs = dict(status=status, reason=repr(err), throttle=throttle,)
    else:
        kwargs = dict(
            photo_id=photo_id,
            status=status,
            author=ina_author,
            review_license=ina_license,
            upload_license=com_license,
            reason=found,
            is_old=is_old,
            throttle=throttle,
            archive=archive,
        )

    reviewed = update_review(page, **kwargs)
    if status == "fail" and reviewed:
        fail_warning(page, ina_license, is_old)

    return reviewed


def main(
    page: Optional[pywikibot.page.BasePage] = None,
    total: int = 0,
    start: Optional[str] = None,
) -> None:
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
        throttle = utils.Throttle(config.get("edit_throttle", 60))
        while (not total) or (i < total):
            for page in files_to_check(start):
                if total and i >= total:
                    break
                i += 1

                try:
                    check_config()
                    review_file(page)
                except (pywikibot.UserBlocked, RestartBot) as err:
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
                else:
                    running = True
                throttle.throttle()
            else:
                # If the for loop drops out, there are no more pages right now
                if running:
                    running = False
                    logger.warning("Out of pages to check!")
                # May need to adjust this number depending on load
                time.sleep(300)


config, conf_ts = get_config()
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
        type=int,
        help="review no more than this number of files in automatic mode",
        default=0,
    )
    parser.add_argument(
        "--ignore-runpage",
        action="store_true",
        dest="ignore_runpage",
        help="skip the runpage check for testing",
    )
    parser.add_argument(
        "--start", action="store", help="sortkey to start iterating at", default=None,
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
        main(total=args.total, start=args.start)
    elif args.file and "File" in args.file:
        main(page=pywikibot.Page(site, args.file))
else:
    run_override = False
    simulate = False

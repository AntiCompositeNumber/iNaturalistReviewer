#!/usr/bin/env python3
# coding: utf-8
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2023 AntiCompositeNumber

import argparse
import datetime
import hashlib
import itertools
import json
import logging
import logging.config
import os
import re
import string
import time
import urllib.parse
from hmac import compare_digest
from io import BytesIO
from pathlib import Path

import imagehash  # type: ignore
import mwparserfromhell as mwph  # type: ignore
import pywikibot  # type: ignore
import pywikibot.pagegenerators as pagegenerators  # type: ignore
import requests
import PIL.Image  # type: ignore
import waybackpy

from typing import NamedTuple, Optional, Set, Tuple, Dict, Union, cast, Callable, List
from typing import Any, Iterator

import acnutils

__version__ = "2.7.1"

logger = acnutils.getInitLogger("inrbot", level="VERBOSE", filename="inrbot.log")

site = pywikibot.Site("commons", "commons")
username = site.username()
summary_tag = f"(inrbot {__version__})"
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

compare_methods: List[Tuple[str, Callable]] = []
pre_save_hooks: List[Callable] = []
id_hooks: List[Callable] = []
status_hooks: List[Callable] = []
lock_hooks: List[Callable] = []


class iNaturalistID(NamedTuple):
    id: str
    type: str
    url: str = ""

    def __str__(self):
        return f"https://www.inaturalist.org/{self.type}/{self.id}"

    def __eq__(self, other):
        if isinstance(other, iNaturalistID):
            return self.id == other.id and self.type == other.type
        elif isinstance(other, iNaturalistImage):
            return self.id == other.id.id and self.type == other.id.type
        else:
            return NotImplemented


class RestartBot(RuntimeError):
    pass


class ProcessingError(Exception):
    def __init__(self, reason_code: str, description: str = ""):
        self.reason_code = reason_code
        self.description = description


class StopReview(Exception):
    def __init__(self, reason: str):
        self.reason = reason


class ExponentialRateLimit:
    """Provide an exponential backoff based on calls to failure()

    Unlike acnutils.Throttle, this throttle is not self-enforcing.
    Instead, call should_run() to determine if a request to a flaky service
    should be made.
    """

    def __init__(
        self, interval_seconds: int, base: int, max_fails: int = 0, log_name: str = ""
    ) -> None:
        """
        :param interval_seconds: Delay interval, in seconds.
        :param base: Base of exponential delay
        :param max_fails: Number of failures beyond which delay should not increase.
            Set to 0 for no maximum.
        """
        self.max_fails = max_fails
        self.interval = interval_seconds
        self.base = base
        self.fails = 0
        self.max_fails = max_fails
        self.last_request = 0.0
        self.logger = logger.getChild(log_name or "ExponentialRateLimit")

    def success(self) -> None:
        if self.fails >= 0:
            self.fails = self.fails - 1
        self.last_request = time.monotonic()

    def failure(self) -> None:
        if self.max_fails == 0 or self.fails < self.max_fails:
            self.fails = self.fails + 1
        else:
            self.logger.error(
                f"Maximum failures exceeded ({self.fails=} >= {self.max_fails=})"
            )

        self.last_request = time.monotonic()

    def backoff_seconds(self) -> int:
        return self.interval * (self.base**self.fails)

    def should_run(self) -> bool:
        if self.fails == 0:
            return True

        backoff = self.backoff_seconds()
        self.logger.debug(f"{self.fails=}, {backoff=}")
        return self.last_request + backoff <= time.monotonic()


petscan_backoff = ExponentialRateLimit(
    interval_seconds=60, base=6, max_fails=4, log_name="petscan_backoff"
)


def get_config() -> Tuple[dict, datetime.datetime]:
    """Load on-wiki configuration"""
    page = pywikibot.Page(site, "User:iNaturalistReviewBot/config.json")
    conf_json = json.loads(page.text)
    logger.info(f"Loaded config from {page.title(as_link=True)}")
    logger.debug(json.dumps(conf_json, indent=2))
    ts = datetime.datetime.utcnow()
    return conf_json, ts


def check_config() -> None:
    page = pywikibot.Page(site, "User:iNaturalistReviewBot/config.json")
    if conf_ts and page.latest_revision.timestamp > conf_ts:
        raise RestartBot("Configuration has been updated, bot will restart")


def init_compare_methods() -> None:
    global compare_methods
    compare_methods = []
    if "sha1" in config["compare_methods"]:
        compare_methods.append(("sha1", compare_sha1))
    if "phash" in config["compare_methods"]:
        compare_methods.append(("phash", compare_phash))


def files_to_check(start: Optional[str] = None) -> Iterator[pywikibot.page.BasePage]:
    """Iterate list of files needing review from Commons"""
    category = pywikibot.Category(site, "Category:INaturalist review needed")
    do_heartbeat()
    for page in pagegenerators.CategorizedPageGenerator(
        category, namespaces=6, start=start
    ):
        yield page


def untagged_files_to_check() -> Iterator[pywikibot.page.BasePage]:
    if not (config.get("find_untagged") and petscan_backoff.should_run()):
        pages = []
    else:
        try:
            res = session.get(
                config["petscan_url"], params=config["untagged_petscan_query"]
            )
            res.raise_for_status()

            data = res.json()
            assert data["n"] == "result"
            pages = data["*"][0]["a"]["*"]
            petscan_backoff.success()
        except Exception as err:
            logger.warning(f"Failed to get data from {res.url}", exc_info=err)
            pages = []
            petscan_backoff.failure()
        logger.info(f"Found {len(pages)} untagged files to check")

    # Whether we get data from PetScan is unrelated to the health of inrbot
    do_heartbeat()
    for page_data in pages:
        yield pywikibot.FilePage(site, title=page_data["title"])


def gbif_to_ina_url(url: urllib.parse.ParseResult) -> str:
    path = url.path.split(sep="/")
    if path[1] != "occurrence":
        return ""
    api_url = f"https://api.gbif.org/v1/occurrence/{path[2]}"
    res = session.get(api_url)
    res.raise_for_status()
    return res.json().get("references", "")


def parse_ina_url(raw_url: str) -> Optional[iNaturalistID]:
    """Parses an iNaturalist URL into an iNaturalistID named tuple"""
    url = urllib.parse.urlparse(raw_url)
    path = url.path.split(sep="/")
    netloc = url.netloc.lower()
    if len(path) == 3 and any(
        netloc.endswith(domain) for domain in config["inaturalist_domains"]
    ):
        return iNaturalistID(type=path[1], id=str(path[2]))
    elif len(path) == 4 and netloc in (
        "inaturalist-open-data.s3.amazonaws.com",
        "static.inaturalist.org",
    ):
        return iNaturalistID(type=path[1], id=str(path[2]))
    elif len(path) == 3 and netloc == "www.gbif.org":
        return parse_ina_url(gbif_to_ina_url(url))
    else:
        return None


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

    def __repr__(self) -> str:
        paras = ", ".join(
            f"{key}={repr(value)}" for key, value in self.__dict__.items()
        )
        return f"{type(self).__name__}({paras})"

    def __eq__(self, other):
        if isinstance(other, Image):
            return self.id == other.id
        elif isinstance(other, iNaturalistID):
            return self.id == other
        else:
            return NotImplemented


class iNaturalistImage(Image):
    _cache: Dict[iNaturalistID, str] = {}

    def __init__(self, id: iNaturalistID, **kwargs):
        self.id = id
        super().__init__(**kwargs)

    @property
    def raw(self) -> bytes:
        if not self._raw:
            self._raw = acnutils.retry(get_ina_image, 3, photo=self.id)
        return cast(bytes, self._raw)

    @property
    def image(self) -> PIL.Image.Image:
        if not self._image:
            self._image = PIL.Image.open(BytesIO(self.raw))
        return self._image

    @property
    def sha1(self) -> str:
        if not self._sha1:
            if self.id in self._cache:
                self._sha1 = self._cache[self.id]
            else:
                sha1sum = hashlib.sha1()
                sha1sum.update(self.raw)
                self._sha1 = sha1sum.hexdigest()
                self._cache[self.id] = self._sha1
        return self._sha1


class CommonsImage(Image):
    def __init__(self, page: pywikibot.FilePage, **kwargs):
        self.page = page
        if self.page:
            self.page.get(force=True)
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


def compare_sha1(com_img: CommonsImage, ina_img: iNaturalistImage) -> bool:
    logger.debug(f"Commons sha1sum:     {com_img.sha1}")
    logger.debug(f"iNaturalist sha1sum: {ina_img.sha1}")
    return compare_digest(com_img.sha1, ina_img.sha1)


def compare_phash(com_img: CommonsImage, ina_img: iNaturalistImage) -> bool:
    diff = com_img.phash - ina_img.phash
    logger.debug(f"PHash Hamming distance: {diff}")
    return diff <= config.get("max_phash_dist", 4)


def get_ina_image(photo: iNaturalistID, final: bool = False) -> bytes:
    """Download original photo from iNaturalist"""
    if photo.url:
        extension = photo.url.partition("?")[0].rpartition(".")[2]
        domain = photo.url.partition("//")[2].partition("/")[0]
    else:
        extension = "jpeg"
        domain = "inaturalist-open-data.s3.amazonaws.com"
    # TODO: Replace this hardcoded URL
    url = f"https://{domain}/photos/{photo.id}/original.{extension}"
    response = session.get(url)
    if response.status_code == 403 and not final:
        return get_ina_image(photo._replace(url=url.replace("jpeg", "jpg")), final=True)
    response.raise_for_status()
    return response.content


def bytes_throttle(length: int) -> None:
    hour_limit = 4.5e9
    day_limit = 23.5e9
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


def do_heartbeat() -> None:
    """Update the timestamp on a file (if provided)

    Works with inrbot-healthcheck.sh when the HEARTBEAT_FILE environment variable is set
    """
    if os.environ.get("HEARTBEAT_FILE"):
        Path(os.environ["HEARTBEAT_FILE"]).touch()


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
        name = template.name.lower().strip()
        if name in self.aliases:
            return True
        elif name == "self":
            return True
        return False


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


class CommonsPage:
    def __init__(
        self,
        page: pywikibot.FilePage,
        throttle: Optional[acnutils.Throttle] = None,
        ina_throttle: acnutils.Throttle = acnutils.Throttle(10),
    ) -> None:
        self.page = page
        self._com_license: Optional[str] = None
        self._ina_license: Optional[str] = None
        self._status = ""
        self._ina_author: Optional[str] = None
        self._ina_data: dict = {}
        self._is_old: Optional[bool] = None
        self._no_del: Optional[bool] = None
        self._archive = ""
        self.throttle = throttle
        self.ina_throttle = ina_throttle
        self.reason = ""
        self._photo_id: Optional[iNaturalistID] = None
        self._raw_photo_id: Optional[iNaturalistID] = None
        self._obs_id: Optional[iNaturalistID] = None
        self._locked = False
        self.photo_id_source = ""
        self.log_page = pywikibot.Page(site, config["untagged_log_page"])

    @property
    def locked(self) -> bool:
        return self._locked

    @locked.setter
    def locked(self, value: bool):
        if self._locked is False:
            self._locked = value
        elif value is False:
            raise TypeError("Can not unlock parameters")

    def lock(self):
        if self.locked is False:
            for hook in lock_hooks:
                hook(self)
            self.locked = True

    def _set_locking(self, attr: str, value: Any) -> None:
        if not self.locked:
            setattr(self, attr, value)
        else:
            raise TypeError(f"{attr[1:]} has already been read, and can not be changed")

    def _get_locking_str(self, attr: str, setter: Optional[Callable] = None) -> str:
        if getattr(self, attr) is None:
            if self.locked:
                setattr(self, attr, "")
            elif setter is not None:
                setter()
            else:
                raise AttributeError(attr[1:])
        return getattr(self, attr)

    def check_can_run(self) -> bool:
        """Determinies if the bot should run on this page and returns a bool."""
        page = self.page
        if (
            # Skip files that are still reported as an error
            (not self.check_has_template() and self.check_untagged_log())
            # Skip if the bot can't edit the page, due to permissions or {{bots}}
            or (not page.has_permission("edit"))
            or (not page.botMayEdit())
            # Skip if there's already a review template with parameters
            or (re.search(r"{{[iI][nN]aturalist[rR]eview *?\|.*?}}", page.text))
        ):
            return False
        else:
            return True

    def check_has_template(self) -> bool:
        return bool(re.search(r"{{[iI][nN]aturalist[rR]eview", self.page.text))

    def check_stop_cats(self) -> None:
        stop_cats = {
            pywikibot.Category(site, title) for title in config["stop_categories"]
        }
        page_cats = set(self.page.categories())
        page_stop = stop_cats & page_cats
        if page_stop:
            raise StopReview(str(page_stop))

    def find_ina_id(self) -> None:
        """Returns an iNaturalistID tuple from wikitext"""
        photos = []
        observations = []

        for url in self.page.extlinks():
            url_id = parse_ina_url(url)
            if (
                url_id is None
                or re.search(r"[A-z]", url_id.id)
                or url_id in photos
                or url_id in observations
            ):
                continue  # pragma: no cover
            elif url_id.type == "observations":
                observations.append(url_id)
            elif url_id.type == "photos":
                photos.append(url_id)

        for hook in id_hooks:
            hook_id = hook(self, observations=observations.copy(), photos=photos.copy())
            if hook_id is None or re.search(r"[A-z]", hook_id.id):
                continue  # pragma: no cover
            elif hook_id.type == "observations":
                observations.insert(0, hook_id)
            elif hook_id.type == "photos":
                photos.insert(0, hook_id)
                observations = []

        if photos and observations:
            self.obs_id = observations[0]
            self.raw_photo_id = photos[0]
        elif observations:
            self.obs_id = observations[0]
            self.raw_photo_id = None
        elif photos:
            self.obs_id = None
            self.raw_photo_id = photos[0]
        else:
            raise ProcessingError("nourl", "No observation ID could be found")

    @property
    def photo_id(self) -> Optional[iNaturalistID]:
        return self._photo_id

    @photo_id.setter
    def photo_id(self, value: Optional[iNaturalistID]):
        self._set_locking("_photo_id", value)

    @property
    def raw_photo_id(self) -> Optional[iNaturalistID]:
        return self._raw_photo_id

    @raw_photo_id.setter
    def raw_photo_id(self, value: Optional[iNaturalistID]):
        self._raw_photo_id = value

    @property
    def obs_id(self) -> Optional[iNaturalistID]:
        if not self._obs_id and not self.locked:
            if self.raw_photo_id:
                self._obs_id = get_observation_from_photo(self.raw_photo_id)
        return self._obs_id

    @obs_id.setter
    def obs_id(self, value: Optional[iNaturalistID]) -> None:
        self._set_locking("_obs_id", value)

    @obs_id.deleter
    def obs_id(self) -> None:
        if not self.locked:
            self._obs_id = None
            del self.ina_data
        else:
            raise TypeError

    @property
    def ina_data(self) -> dict:
        """Make API request to iNaturalist from an ID and ID type

        Returns a dict of the API result
        """
        if not self._ina_data:
            assert self.obs_id
            if self.obs_id.type == "observations":
                url = f"https://api.inaturalist.org/v1/observations/{self.obs_id.id}"
            else:
                raise ProcessingError("apierr", "iNaturalist ID is wrong type")

            if self.throttle:
                self.throttle.throttle()
            try:
                response = session.get(url, headers={"Accept": "application/json"})
                response.raise_for_status()
                response_json = response.json()
            except (ValueError, requests.exceptions.HTTPError) as err:
                raise ProcessingError("apierr", "iNaturalist API error") from err
            else:
                if response_json.get("total_results") != 1:
                    logger.debug(response_json)
                    raise ProcessingError("apierr", f"iNaturalist API error in {url}")
                res = response_json.get("results", [None])[0]
                if not res:
                    raise ProcessingError(
                        "apierr", f"No data recieved from iNaturalist in {url}"
                    )
                self._ina_data = res
        return self._ina_data

    @ina_data.deleter
    def ina_data(self) -> None:
        self._ina_data = {}

    def get_ina_license(self) -> None:
        """Find the image license in the iNaturalist API response

        If a license is found, the Commons template name is returned.
        If no license is found, an empty string is returned.

        The API does not return CC version numbers, but the website has 4.0 links.
        CC 4.0 licenses are assumed.
        """
        assert self.photo_id
        licenses = config["ina_licenses"]
        photos: list = self.ina_data.get("photos", [])
        for photo_data in photos:
            if str(photo_data.get("id")) == self.photo_id.id:
                license_code = photo_data.get("license_code", "null")
                break
        else:
            raise ProcessingError("inatlicense", "No iNaturalist license found")

        if not license_code:
            license_code = "null"

        try:
            self.ina_license = licenses[license_code]
        except KeyError as e:
            raise ProcessingError("inatlicense", "No iNaturalist license found") from e
        logger.info(f"iNaturalist License: {self.ina_license}")

    @property
    def ina_license(self) -> str:
        return self._get_locking_str("_ina_license", self.get_ina_license)

    @ina_license.setter
    def ina_license(self, value: str) -> None:
        self._set_locking("_ina_license", value)

    def find_photo_in_obs(self, recurse: bool = True) -> None:
        """Find the matching image in an iNaturalist observation

        Returns an iNaturalistID named tuple with the photo ID.
        """
        images = [
            iNaturalistImage(
                id=iNaturalistID(type="photos", id=str(photo["id"]), url=photo["url"])
            )
            for photo in self.ina_data["photos"]
        ]
        if len(images) < 1:
            raise ProcessingError("notfound", "No photos in observation")
        elif self.raw_photo_id:
            # False sorts before True, otherwise remains in original order
            # This will sort the matching photo before other photos in the obs,
            # but will still check those other images if no match.
            images.sort(key=lambda image: self.raw_photo_id != image)

        commons_image = CommonsImage(page=self.page)

        for comp_method, comp_func in compare_methods:
            logger.info(f"Comparing photos using {comp_method}")
            for image in images:
                logger.debug(f"Comparing {str(image.id)}")
                try:
                    res = comp_func(com_img=commons_image, ina_img=image)
                except Exception:
                    res = False
                if res:
                    logger.info(f"Match found: {str(image.id)}")
                    self.reason = comp_method
                    self.photo_id = image.id
                    return
                elif self.throttle:
                    self.throttle.throttle()
        if self.raw_photo_id and self.raw_photo_id not in images and recurse:
            del self.obs_id
            self.find_photo_in_obs(recurse=False)
        else:
            raise ProcessingError("notmatching", "No matching photos found")

    def get_ina_author(self):
        self.ina_author = self.ina_data.get("user", {}).get("login", "")
        logger.info(f"Author: {self.ina_author}")

    @property
    def ina_author(self) -> str:
        """Find the image author in the iNaturalist API response

        Returns a string with the username of the iNaturalist contributor
        """
        return self._get_locking_str("_ina_author", self.get_ina_author)

    @ina_author.setter
    def ina_author(self, value: str) -> None:
        self._set_locking("_ina_author", value)

    def get_com_license(self):
        """Find the license template currently used on the Commons page

        Returns the first license template used on the page. If no templates
        are found, return an empty string.
        """

        category = pywikibot.Category(site, "Category:Primary license tags (flat list)")
        templates = set(self.page.itertemplates())
        license_tags = set(category.members(namespaces=10))

        for template in templates:
            if template in license_tags:
                self._com_license = template.title(with_ns=False)
                break
        else:
            logger.info("No Commons license found!")
            self._com_license = ""
        logger.info(f"Commons License: {self.com_license}")

    @property
    def com_license(self) -> str:
        return self._get_locking_str("_com_license", self.get_com_license)

    @com_license.setter
    def com_license(self, value: str) -> None:
        self._set_locking("_com_license", value)

    def compare_licenses(self) -> None:
        free_licenses = set(config["free_licenses"])

        if not self.ina_license:
            # iNaturalist license wasn't found, call in the humans
            self.status = "error"
        elif self.ina_license not in free_licenses:
            # Source license is non-free, failed license review
            self.status = "fail"
        elif self.ina_license == self.com_license:
            # Licenses are the same, license review passes
            self.status = "pass"
        else:
            # Commons license doesn't match iNaturalist, update to match
            self.status = "pass-change"

    @property
    def status(self) -> str:
        """Checks the Commons license against the iNaturalist license

        Returns a string with the status
        Statuses:
            fail:       iNaturalist license is non-free
            error:      Bot could not determine
            pass:       Licenses match
            pass-change: Commons license changed to free iNaturalist license
        """
        if not self.locked:
            if not self._status:
                self.compare_licenses()
            for hook in status_hooks:
                hook(self)
        return self._status

    @status.setter
    def status(self, value):
        self._set_locking("_status", value)

    @status.deleter
    def status(self):
        self.status = ""

    def _file_is_old(self) -> bool:
        if not config.get("old_fail", False):
            return False

        timestamp = self.page.latest_file_info.timestamp
        if (datetime.datetime.now() - timestamp) > datetime.timedelta(
            days=config["old_fail_age"]
        ):
            return True
        else:
            return False

    @property
    def is_old(self) -> bool:
        if self._is_old is None:
            if self.status == "fail":
                self._is_old = self._file_is_old()
            else:
                self._is_old = False
        return self._is_old

    @is_old.setter
    def is_old(self, value: bool) -> None:
        self._set_locking("_is_old", value)

    @property
    def no_del(self) -> bool:
        if self._no_del is None:
            if self.status == "fail":
                page_templates = set(self.page.itertemplates())
                check_templates = {
                    pywikibot.Page(site, "Template:OTRS received"),
                    pywikibot.Page(site, "Template:Deletion template tag"),
                }
                self._no_del = not page_templates.isdisjoint(check_templates)
            else:
                self._no_del = False
        return self._no_del

    @no_del.setter
    def no_del(self, value) -> None:
        self._set_locking("_no_del", value)

    @property
    def archive(self) -> str:
        if not self._archive:
            if config.get("use_wayback") and self.status in ("pass", "pass-change"):
                self.get_old_archive()
                if not self._archive:
                    self.save_archive()
            elif self.status == "fail" or (
                self.status != "error" and config.get("wayback_get", True)
            ):
                self.get_old_archive()
        return self._archive

    @archive.setter
    def archive(self, value: str) -> None:
        self._archive = value

    def save_archive(self) -> None:
        try:
            url = waybackpy.Url(str(self.photo_id), user_agent).save()
            assert url.archive_url is not None
            self.archive = url.archive_url
        except Exception as err:
            logger.warning("Failed to get archive", exc_info=err)
            self.archive = ""

    def get_old_archive(self) -> None:
        try:
            url = waybackpy.Url(str(self.photo_id), user_agent).oldest()
            assert url.archive_url is not None
            self.archive = url.archive_url
        except Exception as err:
            logger.info("Failed to get archive", exc_info=err)
            self.archive = ""
        else:
            if self.status == "fail":
                self.status = "fail-archive"

    def uploader_talk(self) -> pywikibot.page.Page:
        return pywikibot.Page(site, f"User talk:{self.page.oldest_file_info.user}")

    def update_review(self) -> bool:
        """Updates the wikitext with the review status"""
        logger.info(f"Status: {self.status} ({self.reason})")
        self.lock()
        code = mwph.parse(self.page.text)
        template = self.make_template()
        changed = False
        if self.check_has_template():
            # Already tagged for review, replace the existing template
            for review_template in code.ifilter_templates(
                matches=lambda t: t.name.strip().lower() == "inaturalistreview"
            ):
                code.replace(review_template, template)
                changed = True
        else:
            # Check for normal {{LicenseReview}} template
            for review_template in code.ifilter_templates(
                matches=lambda t: bool(re.search(r"[Ll]icense ?[Rr]eview", str(t)))
            ):
                code.replace(review_template, template)
                changed = True

            if not changed:
                # Not already tagged, try to put the review template under the license
                if self.com_license:
                    aliases = Aliases(self.com_license)
                    for pt2 in code.ifilter_templates(matches=aliases.is_license):
                        code.insert_after(pt2, "\n" + template)
                        changed = True
                else:
                    for node in code.ifilter(
                        matches=lambda n: bool(
                            re.search(r"(\[\[Category:|\{\{Uncategorized)", str(n))
                        )
                    ):
                        code.insert_before(node, template + "\n\n")
                        changed = True
                        break
                    else:
                        code.append("\n\n" + template)
                        changed = True

        if not changed:
            logger.warn("Page not changed")
            return False

        if self.status == "pass-change":
            if self.com_license:
                aliases = Aliases(self.com_license)
                for pt2 in code.ifilter_templates(matches=aliases.is_license):
                    code.replace(pt2, ("{{%s}}" % self.ina_license))
            else:
                code.insert_before(template, ("{{%s}}" % self.ina_license))

        if self.status == "fail" and not self.no_del:
            code.insert(
                0,
                string.Template(
                    config["old_fail_tag"] if self.is_old else config["fail_tag"]
                ).safe_substitute(
                    review_license=self.ina_license,
                    source_url=str(self.photo_id) if self.photo_id else "",
                ),
            )

        if self.status in ["pass", "pass-change"] and config.get("tag_source"):
            self.add_source_tag(code)

        if self.throttle is not None:
            self.throttle.throttle()
        try:
            self.save_page(str(code))
        except Exception as err:
            logging.exception(err)
            return False
        else:
            return True

    def make_template(self) -> str:
        """Constructs the iNaturalistreview template"""
        self.lock()
        if self.status == "stop":
            return ""
        template = string.Template(config[self.status])
        text = template.safe_substitute(
            status=self.status,
            author=self.ina_author,
            source_url=str(self.photo_id) if self.photo_id else "",
            review_date=datetime.date.today().isoformat(),
            reviewer=username,
            review_license=self.ina_license,
            upload_license=self.com_license,
            reason=self.reason,
            archive=self.archive,
        )
        return text

    def add_source_tag(self, code: mwph.wikicode.Wikicode) -> None:
        source_tag = ""
        templates = set(self.page.itertemplates())
        if not self.obs_id or not config["tag_source"]:
            return
        if pywikibot.Page(site, "Template:INaturalist") not in templates:
            source_tag += "\n{{iNaturalist|%s}}" % self.obs_id.id

        gbif_links = [
            link
            for link in self.ina_data.get("outlinks", [])
            if link["source"] == "GBIF"
        ]
        if gbif_links and pywikibot.Page(site, "Template:Gbif") not in templates:
            gbif_id = gbif_links[0]["url"].split("/")[-1]
            source_tag += "\n{{gbif|%s}}" % gbif_id

        if not source_tag:
            return

        try:
            # Place templates at the bottom of =={{int:filedesc}}==,
            # after any other templates but before categories/other text
            prev = code.get_sections(matches="filedesc")[0].filter_templates(
                recursive=False
            )[-1]
        except IndexError:
            # If there is no Summary section, just place after {{iNaturalistreview}}
            prev = code.filter_templates(
                matches=lambda t: t.name.strip().lower() == "inaturalistreview"
            )[0]

        code.insert_after(prev, source_tag)

    def save_page(self, new_text: str) -> None:
        """Replaces the wikitext of the specified page with new_text

        If the global simulate variable is true, the wikitext will be printed
        instead of saved to Commons.
        """

        summary = string.Template(config["review_summary"]).safe_substitute(
            status=self.status,
            review_license=self.ina_license,
            version=__version__,
            tag=summary_tag,
        )
        for hook in pre_save_hooks:
            hook(
                self,
                new_text=new_text,
                summary=summary,
            )
        if not simulate:
            acnutils.check_runpage(site, override=run_override)
            logger.info(f"Saving {self.page.title()}")
            acnutils.retry(
                acnutils.save_page,
                3,
                text=new_text,
                page=self.page,
                summary=summary,
                bot=False,
                minor=False,
            )
        else:
            logger.info("Saving disabled")
            logger.debug(summary)
            logger.debug(new_text)

    def fail_warning(self) -> None:
        user_talk = self.uploader_talk()
        message = string.Template(
            config["old_fail_warn"] if self.is_old else config["fail_warn"]
        ).safe_substitute(
            filename=self.page.title(with_ns=True),
            review_license=self.ina_license,
            source_url=str(self.photo_id) if self.photo_id else "",
        )
        summary = string.Template(config["review_summary"]).safe_substitute(
            status="fail",
            review_license=self.ina_license,
            version=__version__,
            tag=summary_tag,
        )
        if not simulate:
            acnutils.check_runpage(site, override=run_override)
            logger.info(f"Saving {user_talk.title()}")
            acnutils.retry(
                acnutils.save_page,
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

    def log_untagged_error(self) -> None:
        if simulate:
            return
        if self.page.title() not in self.log_page.text:
            message = string.Template(config["untagged_log_line"]).safe_substitute(
                status=self.status,
                reason=self.reason,
                link=self.page.title(as_link=True, textlink=True),
            )
            summary = string.Template(config["untagged_log_summary"]).safe_substitute(
                status=self.status,
                reason=self.reason,
                link=self.page.title(as_link=True, textlink=True),
                version=__version__,
                tag=summary_tag,
            )
            acnutils.check_runpage(site, override=run_override)
            acnutils.retry(
                acnutils.save_page,
                3,
                text=message,
                page=self.log_page,
                summary=summary,
                bot=False,
                minor=False,
                mode="append",
            )

    def remove_untagged_log(self) -> None:
        """
        Removes a file from the untagged error log
        """
        new_text, changes = re.subn(
            r"^.*?{0}.*\n?".format(re.escape(str(self.page.title()))),
            "",
            self.log_page.text,
            flags=re.MULTILINE,
        )
        summary = string.Template(
            config["untagged_remove_log_summary"]
        ).safe_substitute(
            link=self.page.title(as_link=True, textlink=True),
            version=__version__,
            tag=summary_tag,
        )

        if changes == 0:
            return
        if simulate:
            logger.debug(summary)
            logger.debug(new_text)
        else:
            acnutils.retry(
                acnutils.save_page,
                3,
                text=new_text,
                page=self.log_page,
                summary=summary,
                bot=False,
                minor=False,
            )

    def check_untagged_log(self) -> bool:
        """
        Returns True if the file is on the untagged log
        """
        for page in self.log_page.linkedPages(namespaces=6):
            if page == self.page:
                return True
        return False

    def review_file(
        self, throttle: Optional[acnutils.Throttle] = None
    ) -> Optional[bool]:
        """Performs a license review on the input page

        inpage must be in the file namespace.

        Returns None if the file was skipped
        Returns False if there was an error during review
        Returns True if the file was successfully reviewed (pass or fail)
        """
        logger.info(f"Checking {self.page.title(as_link=True)}")

        acnutils.check_runpage(site, override=run_override)
        if not self.check_can_run():
            return None

        #####
        try:
            self.check_stop_cats()
            # Get iNaturalistID
            self.find_ina_id()
            logger.info(f"ID found in wikitext: {self.obs_id} {self.raw_photo_id}")

            try:
                self.find_photo_in_obs()
            except ProcessingError as err:
                if (
                    err.reason_code in ("apierr", "notfound")
                    and self.raw_photo_id
                    and self.obs_id
                ):
                    # Observation ID probably doesn't exist.
                    # If we've got a photo ID, try that.
                    del self.obs_id
                    self.find_photo_in_obs()
                else:
                    raise
            self.compare_licenses()
            self.get_ina_author()
            self.archive

        except ProcessingError as err:
            logger.info("Processing failed:", exc_info=err)
            self.status = "error"
            self.reason = err.reason_code
        except StopReview as err:
            logger.info(f"Image already reviewed, contains {err.reason}")
            self.status = "stop"
            return False
        except (acnutils.RunpageError, KeyboardInterrupt, ConnectionError) as err:
            raise err
        except Exception as err:
            logger.exception(err)
            self.status = "error"
            self.reason = repr(err)

        if self.status == "error" and not self.check_has_template():
            # Not previously tagged, don't need to throw an error message on it.
            logger.info("Skipping...")
            self.log_untagged_error()
            # TODO: report out failures/maintain skip list

            return False
        reviewed = self.update_review()
        if self.status == "fail" and reviewed and not self.no_del:
            self.fail_warning()

        if reviewed:
            self.remove_untagged_log()

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
        cpage = CommonsPage(pywikibot.FilePage(page))
        cpage.review_file()
    else:
        # Otherwise, run automatically
        # If total is 0, run continuously.
        # If total is non-zero, check that many files
        logger.info("Beginning loop")
        i = 0
        running = True
        throttle = acnutils.Throttle(config.get("edit_throttle", 60))
        while (not total) or (i < total):
            for page in itertools.chain(
                files_to_check(start), untagged_files_to_check()
            ):
                do_heartbeat()
                try:
                    cpage = CommonsPage(pywikibot.FilePage(page))
                except ValueError:
                    continue

                if total and i >= total:
                    break
                i += 1

                try:
                    check_config()
                    cpage.review_file()
                except (acnutils.RunpageError, RestartBot, ConnectionError) as err:
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
                else:
                    time.sleep(60)


config, conf_ts = get_config()
init_compare_methods()
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
        "--start",
        action="store",
        help="sortkey to start iterating at",
        default=None,
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

    site.login()
    if args.auto:
        main(total=args.total, start=args.start)
    elif args.file and "File" in args.file:
        main(page=pywikibot.Page(site, args.file))
else:
    run_override = False
    simulate = False

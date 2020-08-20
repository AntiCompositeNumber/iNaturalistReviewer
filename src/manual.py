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

import click
import pywikibot
import pywikibot.bot
import logging
import os
import re
import difflib
from typing import Sequence, Dict

os.environ["LOG_FILE"] = "stderr"

import inrbot  # noqa: E402

site = inrbot.site
logger = logging.getLogger("manual")
ids: Dict[pywikibot.Page, inrbot.iNaturalistID] = {}

inrbot.config.update(
    {
        "fail_tag": "{{copyvio|License review not passed: "
        "iNaturalist author is using $review_license}}\n",
        "fail_warn": "\n\n{{subst:Copyvionote |1=$filename "
        "|2=License review "
        "not passed: iNaturalist author is using $review_license }} ~~~~",
        "review_summary": "Semi-automatic license review: "
        "$status $review_license (inrbot $version)",
        "old_fail_warn": "\n\n{{subst:image permission|1=$filename}} "
        "License review not passed: iNaturalist author is using $review_license. ~~~~",
    }
)


def id_hook(
    page: pywikibot.Page,
    observations: Sequence[inrbot.iNaturalistID] = [],
    photos: Sequence[inrbot.iNaturalistID] = [],
    **kwargs,
):
    try:
        return ids[page]
    except KeyError:
        return ask_url(page, observations=observations, photos=photos)
    return None


def manual_compare(
    com_img: inrbot.CommonsImage, ina_img: inrbot.iNaturalistImage, **kwargs
):
    if ids.get(com_img.page, None) == ina_img.id and ina_img.id.type == "photos":
        return True
    else:
        return ask_compare(com_img, ina_img)


def check_can_run(page: pywikibot.page.BasePage) -> bool:
    """Alternate check_can_run to monkey-patch into inrbot"""
    if (
        (page.title() in inrbot.skip)
        or (not page.has_permission("edit"))
        or (not page.botMayEdit())
        or (not re.search("{{[iI][nN]aturalist[rR]eview", page.text))
    ):
        return False
    else:
        return True


def pre_save(page, new_text, summary, status, review_license, **kwargs):
    print(
        f"{page.title(as_link=True)} reviewed with status {status} "
        "and license {review_license}"
    )
    if status == "error":
        raise inrbot.StopReview

    diff = difflib.unified_diff(
        page.get().split("\n"), new_text.split("\n"), lineterm=""
    )
    print("\n".join(diff))
    try:
        choice = pywikibot.bot.input_yn("Save the page?", default=True)
    except pywikibot.bot.QuitKeyboardInterrupt as e:
        raise KeyboardInterrupt from e
    if choice:
        return new_text, summary
    else:
        raise pywikibot.bot.ChoiceException


inrbot.id_hooks.append(id_hook)
inrbot.compare_methods.insert(0, ("manual", manual_compare))
inrbot.check_can_run = check_can_run
inrbot.pre_save_hooks.append(pre_save)


def ask_url(
    page: pywikibot.Page,
    observations: Sequence[inrbot.iNaturalistID] = [],
    photos: Sequence[inrbot.iNaturalistID] = [],
):
    if observations:
        print(f"Observation ID found: {str(observations[0])}")
    if photos:
        print(f"Photo ID found: {str(photos[0])}")
    url = input(f"iNaturalist URL for {page.full_url()} (leave blank for no change): ")
    ina_id = inrbot.parse_ina_url(url)
    ids[page] = ina_id
    return ina_id


def ask_compare(com_img: inrbot.CommonsImage, ina_img: inrbot.iNaturalistImage):
    com_img.image.show(title=com_img.page.title())
    ina_img.image.show(title=str(ina_img.id))
    res = pywikibot.bot.input_yn("Do these images match?", default=False)
    return res


@click.command()
@click.argument("target")
@click.option("--url")
def main(target, url=""):
    if target == "auto":
        cat = pywikibot.Category(
            site, "Category:iNaturalist images needing human review"
        )
        for page in cat.iterpages():
            inrbot.review_file(page)
    else:
        page = pywikibot.FilePage(site, target)
        if url:
            ids[page] = inrbot.parse_ina_url(url)
        inrbot.review_file(page)


if __name__ == "__main__":
    main()

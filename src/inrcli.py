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
import pywikibot  # type: ignore
import pywikibot.bot  # type: ignore
import logging
import os
import re
import difflib
from typing import Sequence, Dict, Optional

os.environ["LOG_FILE"] = "stderr"

import inrbot  # noqa: E402

site = inrbot.site
logger = logging.getLogger("manual")
ids: Dict[pywikibot.Page, Optional[inrbot.iNaturalistID]] = {}

inrbot.config.update(
    {
        "fail_tag": "{{copyvio|License review not passed: "
        "iNaturalist author is using $review_license}}\n",
        "fail_warn": "\n\n{{subst:Copyvionote |1=$filename "
        "|2=License review "
        "not passed: iNaturalist author is using $review_license }} ~~~~",
        "review_summary": "Semi-automatic license review: "
        "$status $review_license (inrcli $version)",
        "old_fail_warn": "\n\n{{subst:image permission|1=$filename}} "
        "License review not passed: iNaturalist author is using $review_license. ~~~~",
    }
)


def manual_compare(
    com_img: inrbot.CommonsImage, ina_img: inrbot.iNaturalistImage, **kwargs
):
    if ids.get(com_img.page, None) == ina_img.id and ina_img.id.type == "photos":
        return True
    else:
        return ask_compare(com_img, ina_img)


def ask_compare(com_img: inrbot.CommonsImage, ina_img: inrbot.iNaturalistImage):
    com_img.image.show(title=com_img.page.title())
    ina_img.image.show(title=str(ina_img.id))
    res = click.confirm("Do these images match?", default=False)
    return res


inrbot.compare_methods.insert(0, ("manual", manual_compare))


class ManualCommonsPage(inrbot.CommonsPage):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def check_can_run(self) -> bool:
        """Determinies if the bot should run on this page and returns a bool."""
        page = self.page
        if (
            (page.title() in inrbot.skip)
            or (not page.has_permission("edit"))
            or (not page.botMayEdit())
            or (not re.search("{{[iI][nN]aturalist[rR]eview", page.text))
        ):
            return False
        else:
            return True

    def get_old_archive_(self):
        return super().get_old_archive()

    def get_old_archive(self):
        # Archives will have already been reviewed by the archive_status_hook
        return ""

    def archive_status_hook(self) -> None:
        if self._status == "fail":
            archive = self.get_old_archive_()
            if archive:
                print(
                    f"This file would fail because of the {self.ina_license} license, "
                    f"but an archived copy is available at {archive}."
                )
                new_license = click.prompt(
                    "Archive license (leave blank for no change)"
                )
                if new_license:
                    self._ina_license = new_license
                    self.archive = archive
                    del self.status
                    self.status

    def pre_save(self, new_text, summary, **kwargs):
        print(
            f"{self.page.title(as_link=True)} reviewed with status {self.status} "
            f"and license {self.ina_license}"
        )
        if self.status == "error":
            raise RuntimeError

        diff = difflib.unified_diff(
            self.page.get().split("\n"), new_text.split("\n"), lineterm=""
        )
        print("\n".join(diff))
        choice = click.confirm("Save the page?", default=True)
        if choice:
            return new_text, summary
        else:
            raise RuntimeError

    def id_hook(
        self,
        observations: Sequence[inrbot.iNaturalistID] = [],
        photos: Sequence[inrbot.iNaturalistID] = [],
        **kwargs,
    ):
        try:
            return ids[self.page]
        except KeyError:
            return self.ask_url(observations=observations, photos=photos)
        return None

    def ask_url(
        self,
        observations: Sequence[inrbot.iNaturalistID] = [],
        photos: Sequence[inrbot.iNaturalistID] = [],
    ):
        print(f"Commons page: {self.page.full_url()}")
        if observations:
            print(f"Observation ID found: {str(observations[0])}")
        if photos:
            print(f"Photo ID found: {str(photos[0])}")
        correct_id = click.confirm("Is this ID correct?", default=True)
        if not correct_id:
            url = click.prompt("iNaturalist Photos URL")
            ina_id = inrbot.parse_ina_url(url)
            if observations:
                self.page.text = self.page.text.replace(str(observations[0]), url)
            if photos:
                self.page.text = self.page.text.replace(str(photos[0]), url)
        elif observations and not photos:
            url = click.prompt("iNaturalist Photos URL")
            ina_id = inrbot.parse_ina_url(url)
        elif photos:
            ina_id = photos[0]
        else:
            ina_id = None
        ids[self.page] = ina_id
        return ina_id


inrbot.id_hooks.append(ManualCommonsPage.id_hook)
inrbot.status_hooks.append(ManualCommonsPage.archive_status_hook)
inrbot.pre_save_hooks.append(ManualCommonsPage.pre_save)


@click.command()
@click.argument("target")
@click.option("--url")
@click.option("--simulate/--no-simulate")
def main(target, url="", simulate=False):
    inrbot.simulate = simulate
    if target == "auto":
        cat = pywikibot.Category(
            site, "Category:iNaturalist images needing human review"
        )
        for page in cat.articles(namespaces=6, reverse=True):
            ManualCommonsPage(pywikibot.FilePage(page)).review_file()
            click.confirm("Continue", abort=True, default=True)
    else:
        page = pywikibot.FilePage(site, target)
        if url:
            # TODO: Add validation
            ids[page] = inrbot.parse_ina_url(url)

        ManualCommonsPage(pywikibot.FilePage(page)).review_file()


if __name__ == "__main__":
    main()

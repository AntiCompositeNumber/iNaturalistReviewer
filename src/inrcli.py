#!/usr/bin/env python3
# coding: utf-8
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2023 AntiCompositeNumber

import click
import pywikibot  # type: ignore
import pywikibot.bot  # type: ignore
import logging
import os
import sys
import difflib
import webbrowser
from typing import Sequence, Dict, Optional, Tuple

os.environ["LOG_FILE"] = "stderr"
os.environ["LOG_LEVEL"] = "WARNING"

import inrbot  # noqa: E402

inrbot.run_override = True
inrbot.summary_tag = f"(inrcli {inrbot.__version__})"
site = inrbot.site
logger = logging.getLogger("manual")
ids: Dict[pywikibot.Page, Optional[inrbot.iNaturalistID]] = {}
auto_open = False
last_ina_id = None

inrbot.config.update(
    {
        "fail_tag": "{{copyvio|License review not passed: "
        "iNaturalist author is using $review_license: $source_url}}\n",
        "fail_warn": "\n\n{{subst:Copyvionote |1=$filename "
        "|2=License review "
        "not passed: iNaturalist author is using $review_license: $source_url }} ~~~~",
        "review_summary": "Semi-automatic license review: "
        "$status $review_license $tag",
        "old_fail_warn": "\n\n{{subst:image permission|1=$filename}} "
        "License review not passed: iNaturalist author is "
        "using $review_license: $source_url. ~~~~",
        "use_wayback": False,
    }
)


class SkipFile(Exception):
    pass


def manual_compare(
    com_img: inrbot.CommonsImage, ina_img: inrbot.iNaturalistImage, **kwargs
):
    if ids.get(com_img.page, None) == ina_img.id and ina_img.id.type == "photos":
        return True
    else:
        return ask_compare(com_img, ina_img)


def ask_compare(com_img: inrbot.CommonsImage, ina_img: inrbot.iNaturalistImage):
    if click.confirm(f"Show {ina_img.id}?", default=False):
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
        ):
            return False
        else:
            return True

    def get_old_archive_(self):
        return super().get_old_archive()

    def get_old_archive(self):
        # Archives will have already been reviewed by the archive_status_hook
        if self.status != "fail":
            return super().get_old_archive()
        return ""

    def archive_status_hook(self) -> None:
        if self._status == "fail":
            super().get_old_archive()
            if self.archive:
                print(
                    f"This file would fail because of the {self.ina_license} license, "
                    f"but an archived copy is available at {self.archive}."
                )
                new_license = click.prompt(
                    "Archive license (leave blank for no change)",
                    default=self.ina_license,
                )
                if new_license:
                    self.ina_license = new_license
                    del self.status
                    self.status

    @staticmethod
    def prompt_photo_url(
        default: Optional[str] = None
    ) -> Tuple[Optional[inrbot.iNaturalistID], str]:
        global last_ina_id
        while True:
            # If default is not None, click will repeatedly prompt until it gets
            # an answer. That, however, doesn't mean we got an answer we like.
            url = click.prompt("iNaturalist Photos URL", default=default)
            ina_id = inrbot.parse_ina_url(url)
            if ina_id == last_ina_id:
                if click.confirm(
                    "That's the same URL you gave last time. Are you sure?"
                ):
                    break
                else:
                    continue
            break
        if ina_id is not None:
            last_ina_id = ina_id
            return ina_id, ""
        return ina_id, url

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
        if auto_open:
            webbrowser.open(self.page.full_url())
            if observations and not photos:
                webbrowser.open(str(observations[0]))
            elif photos:
                webbrowser.open(str(photos[0]))

        res = click.prompt(
            "Is this ID correct? [Y/n/r/s/q]",
            default="Y",
            type=click.Choice("ynrsq", case_sensitive=False),
            show_default=False,
            show_choices=False,
        ).lower()
        if res == "y":
            correct_id = True
        elif res == "n":
            correct_id = False
        elif res == "r":
            self.remove_untagged_log()
            raise SkipFile
        elif res == "s":
            raise SkipFile
        elif res == "q":
            sys.exit()

        if not correct_id:
            ina_id, url = self.prompt_photo_url()
            if observations:
                self.page.text = self.page.text.replace(str(observations[0]), url)
            if photos:
                self.page.text = self.page.text.replace(str(photos[0]), url)
        elif observations and not photos:
            ina_id, url = self.prompt_photo_url(default="")
        elif photos:
            ina_id = photos[0]
        else:
            ina_id = None
        ids[self.page] = ina_id
        return ina_id

    def log_untagged_error(self) -> None:
        # Errors while running in CLI do not need to be logged on-wiki
        return


inrbot.id_hooks.append(ManualCommonsPage.id_hook)
inrbot.lock_hooks.append(ManualCommonsPage.archive_status_hook)
inrbot.pre_save_hooks.append(ManualCommonsPage.pre_save)


@click.command()
@click.argument("target")
@click.option("--url")
@click.option("--simulate/--no-simulate")
@click.option("--reverse", is_flag=True, default=False)
@click.option("-o", "--auto-open", "auto_open_", is_flag=True, default=False)
def main(target, url="", simulate=False, reverse=False, auto_open_=False):
    inrbot.simulate = simulate
    global auto_open
    auto_open = auto_open_
    if target == "auto":
        cat = pywikibot.Category(
            site, "Category:iNaturalist images needing human review"
        )
        dtt = pywikibot.Page(site, "Template:Deletion template tag")
        for page in cat.articles(namespaces=6, reverse=reverse):
            if dtt in set(page.itertemplates()):
                continue
            try:
                mcp = ManualCommonsPage(pywikibot.FilePage(page))
                mcp.review_file()
            except SkipFile:
                continue
    elif target == "errors":
        log_page = pywikibot.Page(site, inrbot.config["untagged_log_page"])
        dtt = pywikibot.Page(site, "Template:Deletion template tag")
        for page in log_page.linkedPages(namespaces=6, follow_redirects=True):
            mcp = ManualCommonsPage(pywikibot.FilePage(page))
            if (
                not page.exists()
                or dtt in set(page.itertemplates())
                or mcp.check_has_template()
            ):
                mcp.remove_untagged_log()
                continue
            try:
                mcp.review_file()
            except SkipFile:
                continue
    elif target == "ask":
        while True:
            new_target = click.prompt("Target", default="")
            if not new_target:
                break
            ManualCommonsPage(pywikibot.FilePage(site, new_target)).review_file()
    else:
        page = pywikibot.FilePage(site, target)
        if url:
            # TODO: Add validation
            ids[page] = inrbot.parse_ina_url(url)

        ManualCommonsPage(page).review_file()


if __name__ == "__main__":
    main()

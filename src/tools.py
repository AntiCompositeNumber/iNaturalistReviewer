#!/usr/bin/env python3
# coding: utf-8
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2020 AntiCompositeNumber

import pywikibot  # type: ignore
import logging
import logging.config

import inrbot

logger = logging.getLogger("inrbot.tools")

config = inrbot.config


def potential_files():
    pywikibot
    search = "insource:inaturalist -hastemplate:inaturalistreview "
    stop_cats = [cat.partition(":")[2] for cat in config["stop_categories"]]
    search += " ".join(f'-incategory:"{cat}"' for cat in stop_cats)
    print(search)


if __name__ == "__main__":
    potential_files()

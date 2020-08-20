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


import pywikibot  # type: ignore
import logging
import logging.config

import inrbot
import utils

logging.config.dictConfig(
    utils.logger_config("inrbot.tools", level="VERBOSE", filename="inrbot.log")
)
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

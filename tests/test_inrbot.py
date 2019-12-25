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

import unittest.mock as mock
from collections import namedtuple
import json
from datetime import date
import pywikibot
import sys
import os

_work_dir_ = os.path.dirname(__file__)
sys.path.append(os.path.realpath(_work_dir_ + "/.."))

import src.inrbot as inrbot  # noqa: F401

test_data_dir = os.path.join(_work_dir_, "testdata")
id_tuple = namedtuple("iNaturalistID", "id type")


def test_find_ina_id():
    page = mock.MagicMock()
    extlinks = [
        "http://example.com",
        "https://www.inaturalist.org/observations/15059501",
    ]
    page.extlinks.return_value = extlinks
    ina_id = inrbot.find_ina_id(page)
    compare = id_tuple(id="15059501", type="observations")
    assert ina_id == compare


def test_find_ina_id_none():
    page = mock.MagicMock()
    extlinks = [
        "http://example.com",
    ]
    page.extlinks.return_value = extlinks
    ina_id = inrbot.find_ina_id(page)
    assert ina_id is None


def test_find_ina_id_nourls():
    page = mock.MagicMock()
    extlinks = []
    page.extlinks.return_value = extlinks
    ina_id = inrbot.find_ina_id(page)
    assert ina_id is None


def test_find_ina_id_multiple():
    page = mock.MagicMock()
    extlinks = [
        "https://www.inaturalist.org/photos/12345",
        "https://www.inaturalist.org/observations/15059501",
    ]
    page.extlinks.return_value = extlinks
    ina_id = inrbot.find_ina_id(page)
    compare = id_tuple(id="15059501", type="observations")
    assert ina_id == compare


def test_find_ina_license():
    with open(test_data_dir + "/ina_response.json") as f:
        ina_data = json.load(f)
    photo = id_tuple(id="22483426", type="photos")
    assert inrbot.find_ina_license(ina_data, photo) == "Cc-by-4.0"


def test_find_ina_license_fail():
    with open(test_data_dir + "/ina_response.json") as f:
        ina_data = json.load(f)
    photo = id_tuple(id="12345", type="photos")
    assert inrbot.find_ina_license(ina_data, photo) is None


def test_find_ina_author():
    with open(test_data_dir + "/ina_response.json") as f:
        ina_data = json.load(f)
    assert inrbot.find_ina_author(ina_data) == "dannaguevara"


def test_find_com_license_found():
    site = pywikibot.Site("commons", "commons")
    page = pywikibot.Page(site, "File:Commons-logo-en.svg")
    license = inrbot.find_com_license(page)
    assert license == "Cc-by-sa-3.0"


def test_find_com_license_none():
    site = pywikibot.Site("commons", "commons")
    page = pywikibot.Page(site, "COM:PCP")
    license = inrbot.find_com_license(page)
    assert license is None


def test_check_licenses_pass():
    ina_license = "Cc-by-4.0"
    com_license = "Cc-by-4.0"
    result = inrbot.check_licenses(ina_license, com_license)
    assert result == "pass"


def test_check_licenses_pass_change():
    ina_license = "Cc-by-sa-4.0"
    com_license = "Cc-by-4.0"
    result = inrbot.check_licenses(ina_license, com_license)
    assert result == "pass-change"


def test_check_licenses_fail():
    ina_license = "Cc-by-nd-4.0"
    com_license = "Cc-by-4.0"
    result = inrbot.check_licenses(ina_license, com_license)
    assert result == "fail"


def test_check_licenses_error():
    ina_license = ""
    com_license = ""
    result = inrbot.check_licenses(ina_license, com_license)
    assert result == "error"


def test_update_review_section():
    page = mock.Mock()
    with open(test_data_dir + "/section.txt") as f:
        page.text = f.read()
    photo_id = id_tuple(type="observations", id="11505950")

    save_page = mock.Mock()
    with mock.patch("src.inrbot.save_page", save_page):
        inrbot.update_review(
            page,
            photo_id,
            status="pass",
            author="Author",
            review_license="Cc-by-sa-4.0",
            upload_license="Cc-by-sa-4.0",
        )
    compare = (
        "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass |author=Author "
        "|sourceurl=https://www.inaturalist.org/photo/11505950 "
        f"|reviewdate={date.today().isoformat()} "
        "|reviewer=iNaturalistReviewBot |reviewlicense=Cc-by-sa-4.0}}"
    )
    save_page.assert_called_once
    assert compare in save_page.call_args[0][1]


def test_update_review_section_fail():
    page = mock.Mock()
    with open(test_data_dir + "/section.txt") as f:
        page.text = f.read()
    photo_id = id_tuple(type="observations", id="11505950")

    save_page = mock.Mock()
    with mock.patch("src.inrbot.save_page", save_page):
        inrbot.update_review(
            page,
            photo_id,
            status="fail",
            author="Author",
            review_license="Cc-by-sa-4.0",
            upload_license="Cc-by-sa-4.0",
        )
    compare = (
        "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=fail |author=Author "
        "|sourceurl=https://www.inaturalist.org/photo/11505950 "
        f"|reviewdate={date.today().isoformat()} "
        "|reviewer=iNaturalistReviewBot |reviewlicense=Cc-by-sa-4.0}}"
    )
    save_page.assert_called_once
    assert compare in save_page.call_args[0][1]
    assert "{{copyvio" in save_page.call_args[0][1]


def test_update_review_section_error():
    page = mock.Mock()
    with open(test_data_dir + "/section.txt") as f:
        page.text = f.read()

    save_page = mock.Mock()
    with mock.patch("src.inrbot.save_page", save_page):
        inrbot.update_review(
            page,
            status="error",
        )
    compare = (
        "{{cc-by-sa-4.0}}{{iNaturalistReview |status=error "
        f"|reviewdate={date.today().isoformat()} "
        "|reviewer=iNaturalistReviewBot }}"
    )
    save_page.assert_called_once
    print(save_page.call_args[0][1])
    assert compare in save_page.call_args[0][1]


def test_update_review_section_newline():
    page = mock.Mock()
    with open(test_data_dir + "/section_newline.txt") as f:
        page.text = f.read()
    photo_id = id_tuple(type="observations", id="11505950")

    save_page = mock.Mock()
    with mock.patch("src.inrbot.save_page", save_page):
        inrbot.update_review(
            page,
            photo_id,
            status="pass",
            author="Author",
            review_license="Cc-by-sa-4.0",
            upload_license="Cc-by-sa-4.0",
        )
    compare = (
        "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass |author=Author "
        "|sourceurl=https://www.inaturalist.org/photo/11505950 "
        f"|reviewdate={date.today().isoformat()} "
        "|reviewer=iNaturalistReviewBot |reviewlicense=Cc-by-sa-4.0}}"
    )
    save_page.assert_called_once
    assert compare in save_page.call_args[0][1]


def test_update_review_section_change():
    page = mock.Mock()
    with open(test_data_dir + "/section_change.txt") as f:
        page.text = f.read()
    photo_id = id_tuple(type="observations", id="11505950")

    save_page = mock.Mock()
    with mock.patch("src.inrbot.save_page", save_page):
        inrbot.update_review(
            page,
            photo_id,
            status="pass-change",
            author="Author",
            review_license="Cc-by-sa-4.0",
            upload_license="Cc-by-4.0",
        )
    compare = (
        "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass-change |author=Author "
        "|sourceurl=https://www.inaturalist.org/photo/11505950 "
        f"|reviewdate={date.today().isoformat()} "
        "|reviewer=iNaturalistReviewBot "
        "|reviewlicense=Cc-by-sa-4.0 |uploadlicense=Cc-by-4.0}}"
    )
    save_page.assert_called_once
    assert compare in save_page.call_args[0][1]


def test_update_review_para():
    page = mock.Mock()
    with open(test_data_dir + "/para.txt") as f:
        page.text = f.read()
    photo_id = id_tuple(type="observations", id="11505950")

    save_page = mock.Mock()
    with mock.patch("src.inrbot.save_page", save_page):
        inrbot.update_review(
            page,
            photo_id,
            status="pass",
            author="Author",
            review_license="Cc-by-sa-4.0",
            upload_license="Cc-by-sa-4.0",
        )
    compare = (
        "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass |author=Author "
        "|sourceurl=https://www.inaturalist.org/photo/11505950 "
        f"|reviewdate={date.today().isoformat()} "
        "|reviewer=iNaturalistReviewBot |reviewlicense=Cc-by-sa-4.0}}"
    )
    save_page.assert_called_once
    assert compare in save_page.call_args[0][1]


def test_update_review_para_change():
    page = mock.Mock()
    with open(test_data_dir + "/para_change.txt") as f:
        page.text = f.read()
    photo_id = id_tuple(type="observations", id="11505950")

    save_page = mock.Mock()
    with mock.patch("src.inrbot.save_page", save_page):
        inrbot.update_review(
            page,
            photo_id,
            status="pass-change",
            author="Author",
            review_license="Cc-by-sa-4.0",
            upload_license="Cc-by-4.0",
        )
    compare = (
        "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass-change |author=Author "
        "|sourceurl=https://www.inaturalist.org/photo/11505950 "
        f"|reviewdate={date.today().isoformat()} "
        "|reviewer=iNaturalistReviewBot "
        "|reviewlicense=Cc-by-sa-4.0 |uploadlicense=Cc-by-4.0}}"
    )
    save_page.assert_called_once
    assert compare in save_page.call_args[0][1]


def test_update_review_free():
    page = mock.Mock()
    with open(test_data_dir + "/free.txt") as f:
        page.text = f.read()
    photo_id = id_tuple(type="observations", id="11505950")

    save_page = mock.Mock()
    with mock.patch("src.inrbot.save_page", save_page):
        inrbot.update_review(
            page,
            photo_id,
            status="pass",
            author="Author",
            review_license="Cc-by-sa-4.0",
            upload_license="Cc-by-sa-4.0",
        )
    compare = (
        "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass |author=Author "
        "|sourceurl=https://www.inaturalist.org/photo/11505950 "
        f"|reviewdate={date.today().isoformat()} "
        "|reviewer=iNaturalistReviewBot |reviewlicense=Cc-by-sa-4.0}}"
    )
    save_page.assert_called_once
    assert compare in save_page.call_args[0][1]


def test_update_review_free_change():
    page = mock.Mock()
    with open(test_data_dir + "/free_change.txt") as f:
        page.text = f.read()
    photo_id = id_tuple(type="observations", id="11505950")

    save_page = mock.Mock()
    with mock.patch("src.inrbot.save_page", save_page):
        inrbot.update_review(
            page,
            photo_id,
            status="pass",
            author="Author",
            review_license="Cc-by-sa-4.0",
            upload_license="Cc-by-sa-4.0",
        )
    compare = (
        "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass |author=Author "
        "|sourceurl=https://www.inaturalist.org/photo/11505950 "
        f"|reviewdate={date.today().isoformat()} "
        "|reviewer=iNaturalistReviewBot |reviewlicense=Cc-by-sa-4.0}}"
    )
    save_page.assert_called_once
    assert compare in save_page.call_args[0][1]


def test_update_review_broken():
    page = mock.Mock()
    page.text = "Foo"
    photo_id = id_tuple(type="observations", id="11505950")
    result = inrbot.update_review(
        page,
        photo_id,
        status="pass",
        author="Author",
        review_license="Cc-by-sa-4.0",
        upload_license="Cc-by-sa-4.0",
    )
    assert result is False


def test_make_template():
    photo_id = id_tuple(type="observations", id="11505950")
    template = inrbot.make_template(
        photo_id,
        status="pass",
        author="Author",
        review_license="Cc-by-sa-4.0",
        upload_license="Cc-by-sa-4.0",
    )
    compare = (
        "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass |author=Author "
        "|sourceurl=https://www.inaturalist.org/photo/11505950 "
        f"|reviewdate={date.today().isoformat()} "
        "|reviewer=iNaturalistReviewBot |reviewlicense=Cc-by-sa-4.0}}"
    )
    assert str(template) == compare


def test_make_template_change():
    photo_id = id_tuple(type="observations", id="11505950")
    template = inrbot.make_template(
        photo_id,
        status="pass-change",
        author="Author",
        review_license="Cc-by-sa-4.0",
        upload_license="Cc-by-4.0",
    )
    compare = (
        "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass-change |author=Author "
        "|sourceurl=https://www.inaturalist.org/photo/11505950 "
        f"|reviewdate={date.today().isoformat()} "
        "|reviewer=iNaturalistReviewBot "
        "|reviewlicense=Cc-by-sa-4.0 |uploadlicense=Cc-by-4.0}}"
    )
    assert str(template) == compare

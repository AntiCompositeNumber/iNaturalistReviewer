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
import pytest
import datetime
import inspect
import json
import requests
from datetime import date
import pywikibot  # type: ignore
import sys
import os
import acnutils

_work_dir_ = os.path.dirname(__file__)
sys.path.append(os.path.realpath(_work_dir_ + "/../src"))

import inrbot  # noqa: E402

inrbot.username = "iNaturalistReviewBot"
test_data_dir = os.path.join(_work_dir_, "testdata")
id_tuple = inrbot.iNaturalistID


def test_check_can_run_skip():
    page = pywikibot.FilePage(inrbot.site, "File:Male.svg")
    cpage = inrbot.CommonsPage(page)
    assert isinstance(inrbot.skip, set)
    inrbot.skip.add("File:Male.svg")
    cpage.check_can_run()
    inrbot.skip.remove("File:Male.svg")


def test_check_can_run_protected():
    if (
        inrbot.site.username()
        and "editprotected"
        in pywikibot.User(inrbot.site, inrbot.site.username()).rights()
    ):
        pytest.skip("admins can edit through protection, duh")
    page = pywikibot.FilePage(inrbot.site, "File:Blocked user.svg")
    cpage = inrbot.CommonsPage(page)
    assert not cpage.check_can_run()


def test_check_can_run_exclusion():
    page = pywikibot.FilePage(inrbot.site, "File:Male.svg")
    cpage = inrbot.CommonsPage(page)
    assert not cpage.check_can_run()


@pytest.mark.parametrize(
    "text,expected",
    [
        ("{{iNaturalistreview}}", True),
        ("{{iNaturalistreview|status=error}}", False),
    ],
)
def test_check_can_run_mock(text, expected):
    page = mock.MagicMock(spec=pywikibot.FilePage, autospec=True)
    page.text = text
    cpage = inrbot.CommonsPage(page)
    assert cpage.check_can_run() == expected


def test_check_stop_cats_stop():
    page = mock.MagicMock(spec=pywikibot.FilePage, autospec=True)
    cat = pywikibot.Category(
        inrbot.site, "Category:Items with OTRS permission confirmed"
    )
    page.categories.return_value = [cat]
    cpage = inrbot.CommonsPage(page)
    with pytest.raises(inrbot.StopReview):
        cpage.check_stop_cats()


def test_check_stop_cats_go():
    page = mock.MagicMock(spec=pywikibot.FilePage, autospec=True)
    cat = pywikibot.Category(inrbot.site, "Category:INaturalist review needed")
    page.categories.return_value = [cat]
    cpage = inrbot.CommonsPage(page)
    cpage.check_stop_cats()


def test_files_to_check():
    assert inspect.isgeneratorfunction(inrbot.files_to_check)


def test_untagged_files_to_check():
    next(inrbot.untagged_files_to_check())


@pytest.mark.parametrize(
    "extlinks,expected",
    [
        (
            [
                "http://example.com",
                "https://www.inaturalist.org/observations/15059501",
            ],
            (id_tuple(id="15059501", type="observations"), None),
        ),
        (
            [
                "https://www.inaturalist.org/photos/12345",
                "https://www.inaturalist.org/taxon/123-foobar",
                "https://www.inaturalist.org/observations/15059501",
            ],
            (
                id_tuple(id="15059501", type="observations"),
                id_tuple(id="12345", type="photos"),
            ),
        ),
        (
            ["http://example.com", "https://www.inaturalist.org/photos/12345"],
            (None, id_tuple(id="12345", type="photos")),
        ),
        (
            [
                "http://inaturalist.org/photos/12345",
                "http://inaturalist.org/observations/15059501",
            ],
            (
                id_tuple(id="15059501", type="observations"),
                id_tuple(id="12345", type="photos"),
            ),
        ),
        (
            [
                "http://www.inaturalist.nz/photos/12345",
                "http://www.inaturalist.nz/observations/15059501",
            ],
            (
                id_tuple(id="15059501", type="observations"),
                id_tuple(id="12345", type="photos"),
            ),
        ),
        (
            [
                "https://www.inaturalist.org/photos/12345",
                "https://www.inaturalist.org/photos/12345",
                "https://www.inaturalist.org/observations/example",
            ],
            (None, id_tuple(id="12345", type="photos")),
        ),
        (
            [
                "https://portugal.inaturalist.org/photos/12345",
                "https://portugal.inaturalist.org/observations/15059501",
            ],
            (
                id_tuple(id="15059501", type="observations"),
                id_tuple(id="12345", type="photos"),
            ),
        ),
        (
            [
                "http://example.com",
                "https://static.inaturalist.org/photos/12345/original.jpeg?12345",
            ],
            (None, id_tuple(id="12345", type="photos")),
        ),
        (
            [
                "http://example.com",
                "https://inaturalist-open-data.s3.amazonaws.com"
                "/photos/12345/original.jpeg?12345",
            ],
            (None, id_tuple(id="12345", type="photos")),
        ),
        pytest.param(
            ["https://www.gbif.org/occurrence/2802897480"],
            (id_tuple(id="50526197", type="observations"), None),
            marks=pytest.mark.ext_web,
        ),
    ],
)
def test_find_ina_id(extlinks, expected):
    page = mock.MagicMock()
    page.extlinks.return_value = extlinks
    cpage = inrbot.CommonsPage(page)
    cpage.find_ina_id()
    assert (cpage._obs_id, cpage._raw_photo_id) == expected


@pytest.mark.parametrize("extlinks", [["http://example.com"], []])
def test_find_ina_id_fail(extlinks):
    page = mock.MagicMock()
    page.extlinks.return_value = extlinks
    cpage = inrbot.CommonsPage(page)
    with pytest.raises(inrbot.ProcessingError, match="nourl"):
        cpage.find_ina_id()


def test_find_ina_id_hook():
    page = mock.MagicMock()
    page.extlinks.return_value = ["https://www.inaturalist.org/photos/54321"]
    ext_photo = id_tuple(id="54321", type="photos")
    photo_id = id_tuple(id="12345", type="photos")
    obs_id = id_tuple(id="67890", type="observations")
    hook_1 = mock.MagicMock(return_value=photo_id)
    hook_2 = mock.MagicMock(return_value=obs_id)
    with mock.patch("inrbot.id_hooks", [hook_1, hook_2]):
        cpage = inrbot.CommonsPage(page)
        cpage.find_ina_id()
    assert cpage.raw_photo_id == photo_id
    assert cpage.obs_id == obs_id
    hook_1.assert_called_once_with(cpage, observations=[], photos=[ext_photo])
    hook_2.assert_called_once_with(cpage, observations=[], photos=[photo_id, ext_photo])


@pytest.mark.ext_web
def test_get_ina_data_observation():
    cpage = inrbot.CommonsPage(None)
    cpage.obs_id = id_tuple(id="36885889", type="observations")
    response = cpage.ina_data
    assert response
    assert type(response) is dict


def test_get_ina_data_wrong_endpoint():
    cpage = inrbot.CommonsPage(None)
    cpage.obs_id = id_tuple(id="anticompositenumber", type="people")
    with pytest.raises(inrbot.ProcessingError, match="apierr"):
        cpage.ina_data


def test_get_ina_data_bad_data():
    cpage = inrbot.CommonsPage(None)
    cpage.obs_id = id_tuple(id="36885889", type="observations")
    mock_session = mock.MagicMock()
    mock_session.get.return_value.json.return_value = {"total_results": 1}
    with mock.patch("inrbot.session", mock_session):
        with pytest.raises(inrbot.ProcessingError, match="apierr"):
            cpage.ina_data


def test_get_ina_data_wrong_number():
    cpage = inrbot.CommonsPage(None)
    cpage.obs_id = id_tuple(id="36885889", type="observations")
    mock_session = mock.MagicMock()
    mock_session.get.return_value.json.return_value = {"total_results": 2}
    with mock.patch("inrbot.session", mock_session):
        with pytest.raises(inrbot.ProcessingError, match="apierr"):
            cpage.ina_data


def test_get_ina_data_error():
    cpage = inrbot.CommonsPage(None)
    cpage.obs_id = id_tuple(id="36885889", type="observations")
    mock_session = mock.MagicMock()
    mock_session.get.side_effect = requests.exceptions.HTTPError
    with mock.patch("inrbot.session", mock_session):
        with pytest.raises(inrbot.ProcessingError, match="apierr"):
            cpage.ina_data


def test_ina_sha1_cache():
    ina_id = id_tuple(id="12345", type="photos")
    sha1s = []
    for i in [1, 0]:
        with mock.patch(
            "inrbot.iNaturalistImage.raw",
            new_callable=mock.PropertyMock,
            return_value=b"12345",
        ) as raw:
            ina_img = inrbot.iNaturalistImage(ina_id)
            sha1s.append(ina_img.sha1)
            assert raw.call_count == i

    assert sha1s[0] == sha1s[1]
    ina_id2 = id_tuple(id="54321", type="photos")
    ina_img2 = inrbot.iNaturalistImage(ina_id2)
    with mock.patch(
        "inrbot.iNaturalistImage.raw",
        new_callable=mock.PropertyMock,
        return_value=b"54321",
    ) as raw:
        assert ina_img2.sha1 not in sha1s


def test_find_photo_in_obs_notfound():
    page = mock.MagicMock()
    cpage = inrbot.CommonsPage(page)
    cpage.obs_id = mock.MagicMock()
    cpage._ina_data = {"photos": []}

    with pytest.raises(inrbot.ProcessingError, match="notfound"):
        cpage.find_photo_in_obs()


@pytest.mark.ext_web
@pytest.mark.parametrize("method", ["sha1", "phash"])
def test_find_photo_in_obs_notmatching(method):
    page = pywikibot.FilePage(inrbot.site, "File:Ladona julia at Spectacle Pond.jpg")
    cpage = inrbot.CommonsPage(page)
    cpage.obs_id = id_tuple(id="36885821", type="observations")
    mock_config = {"compare_methods": [method]}

    with mock.patch.dict("inrbot.config", mock_config):
        inrbot.init_compare_methods()
        with pytest.raises(inrbot.ProcessingError, match="notmatching"):
            cpage.find_photo_in_obs()


@pytest.mark.ext_web
@pytest.mark.parametrize("method", ["sha1", "phash"])
def test_find_photo_in_obs_pass(method):
    page = pywikibot.FilePage(inrbot.site, "File:Ladona julia at Spectacle Pond.jpg")
    cpage = inrbot.CommonsPage(page)
    cpage.obs_id = id_tuple(id="36885889", type="observations")
    mock_config = {"compare_methods": [method]}

    with mock.patch.dict("inrbot.config", mock_config):
        inrbot.init_compare_methods()
        cpage.find_photo_in_obs()
    assert cpage.reason.startswith(method)
    assert cpage.photo_id == id_tuple(id="58596675", type="photos")


@pytest.mark.ext_web
def test_find_photo_in_obs_ignore():
    """When raw_photo_id is not in the obs, compare all photos in obs"""
    cpage = inrbot.CommonsPage(None)
    mock_compare = mock.Mock(return_value=False)
    cpage.obs_id = id_tuple(id="36885889", type="observations")
    cpage.raw_photo_id = id_tuple(id="12345", type="photos")

    inrbot.compare_methods = [("mock", mock_compare)]
    with pytest.raises(inrbot.ProcessingError):
        cpage.find_photo_in_obs(recurse=False)
    assert mock_compare.call_count == 3


@pytest.mark.ext_web
def test_find_photo_in_obs_photo():
    """When raw_photo_id is in the obs, it should be processed first
    If it does not match, all photos in obs should be checked"""
    cpage = inrbot.CommonsPage(None)
    cpage.obs_id = id_tuple(id="36885889", type="observations")
    photo_id = id_tuple(id="58596679", type="photos")
    cpage.raw_photo_id = photo_id

    mock_compare = mock.Mock(return_value=False)
    inrbot.compare_methods = [("mock", mock_compare)]
    with pytest.raises(inrbot.ProcessingError):
        cpage.find_photo_in_obs(recurse=False)
    assert mock_compare.call_count == 3
    assert mock_compare.mock_calls[0][2]["ina_img"].id == photo_id


@pytest.mark.ext_web
def test_find_photo_in_obs_changeobs():
    cpage = inrbot.CommonsPage(None)
    cpage.obs_id = id_tuple(id="15059501", type="observations")
    photo_id = id_tuple(id="58596679", type="photos")
    cpage.raw_photo_id = photo_id

    mock_compare = mock.Mock(side_effect=lambda com_img, ina_img: ina_img == photo_id)
    inrbot.compare_methods = [("mock", mock_compare)]
    cpage.find_photo_in_obs()
    assert cpage.photo_id == photo_id


def test_ina_license():
    cpage = inrbot.CommonsPage(None)
    with open(test_data_dir + "/ina_response.json") as f:
        cpage._ina_data = json.load(f)
    cpage.photo_id = id_tuple(id="22483426", type="photos")
    cpage.get_ina_license()
    assert cpage.ina_license == "Cc-by-4.0"


def test_ina_license_fail():
    cpage = inrbot.CommonsPage(None)
    with open(test_data_dir + "/ina_response.json") as f:
        cpage._ina_data = json.load(f)
    cpage.photo_id = id_tuple(id="12345", type="photos")
    with pytest.raises(inrbot.ProcessingError, match="inatlicense"):
        cpage.get_ina_license()


def test_ina_author():
    cpage = inrbot.CommonsPage(None)
    with open(test_data_dir + "/ina_response.json") as f:
        cpage._ina_data = json.load(f)
    cpage.get_ina_author()
    assert cpage.ina_author == "dannaguevara"


def test_com_license_found():
    site = pywikibot.Site("commons", "commons")
    page = pywikibot.FilePage(site, "File:Commons-logo-en.svg")
    cpage = inrbot.CommonsPage(page)
    cpage.get_com_license()
    assert cpage.com_license == "Cc-by-sa-3.0"


def test_com_license_none():
    site = pywikibot.Site("commons", "commons")
    page = pywikibot.Page(site, "COM:PCP")
    cpage = inrbot.CommonsPage(page)
    cpage.get_com_license()
    assert cpage.com_license == ""


def test_com_license_unk():
    site = pywikibot.Site("commons", "commons")
    page = pywikibot.Page(site, "Template:CC-Layout")
    cpage = inrbot.CommonsPage(page)
    with pytest.raises(inrbot.ProcessingError, match="comlicense"):
        cpage.get_com_license()


@pytest.mark.parametrize(
    "ina_license,com_license,expected",
    [
        ("Cc-by-4.0", "Cc-by-4.0", "pass"),
        ("Cc-by-sa-4.0", "Cc-by-4.0", "pass-change"),
        ("Cc-by-4.0", "", "pass-change"),
        ("Cc-by-nd-4.0", "Cc-by-4.0", "fail"),
        ("", "", "error"),
    ],
)
def test_compare_licenses(ina_license, com_license, expected):
    cpage = inrbot.CommonsPage(None)
    cpage.ina_license = ina_license
    cpage.com_license = com_license
    cpage.compare_licenses()
    assert cpage.status == expected


def test_status_hooks():
    def side_effect(self):
        self.status = "foo"

    hook = mock.MagicMock(side_effect=side_effect)
    cpage = inrbot.CommonsPage(None)
    with mock.patch("inrbot.status_hooks", [hook]):
        with mock.patch.object(cpage, "compare_licenses"):
            assert cpage.status == "foo"
    hook.assert_called_once_with(cpage)


def test_status_lock():
    hook = mock.MagicMock()
    compare = mock.MagicMock()
    cpage = inrbot.CommonsPage(None)
    with mock.patch("inrbot.status_hooks", [hook]):
        with mock.patch.object(cpage, "compare_licenses", compare):
            assert cpage.status == ""
            compare.assert_called_once()
            hook.assert_called_once()

            cpage.status = "foo"
            assert cpage.status == "foo"
            compare.assert_called_once()
            assert hook.call_count == 2

            cpage.lock()
            assert cpage.status == "foo"
            compare.assert_called_once()
            assert hook.call_count == 2
            with pytest.raises(TypeError):
                cpage.status = "bar"
            with pytest.raises(TypeError):
                del cpage.status


def test_status_del():
    cpage = inrbot.CommonsPage(None)
    cpage.status = "foo"
    del cpage.status
    with mock.patch.object(cpage, "compare_licenses"):
        assert cpage.status == ""


@pytest.mark.parametrize(
    "status,timestamp,expected",
    [
        ("fail", inrbot.site.server_time(), False),
        ("fail", pywikibot.Timestamp.fromISOformat("2019-01-01T00:00:00Z"), True),
        ("pass", pywikibot.Timestamp.fromISOformat("2019-01-01T00:00:00Z"), False),
    ],
)
def test_is_old(status, timestamp, expected):
    mock_page = mock.Mock(spec=pywikibot.FilePage)
    mock_page.latest_file_info.timestamp = timestamp
    cpage = inrbot.CommonsPage(mock_page)
    cpage.status = status
    assert cpage.is_old == expected


@pytest.mark.parametrize(
    "status,templates,expected",
    [
        ("fail", [pywikibot.Page(inrbot.site, "Template:OTRS received")], True),
        ("fail", [pywikibot.Page(inrbot.site, "Template:Deletion template tag")], True),
        ("fail", [], False),
        (
            "fail",
            [
                pywikibot.Page(inrbot.site, "Template:License template tag"),
                pywikibot.Page(inrbot.site, "Template:OTRS received"),
            ],
            True,
        ),
        ("fail", [pywikibot.Page(inrbot.site, "Template:License template tag")], False),
        ("pass", [pywikibot.Page(inrbot.site, "Template:OTRS received")], False),
    ],
)
def test_no_del(status, templates, expected):
    mock_page = mock.MagicMock(spec=pywikibot.FilePage)
    mock_page.itertemplates.return_value = templates
    cpage = inrbot.CommonsPage(mock_page)
    cpage.status = status
    assert cpage.no_del == expected


@pytest.mark.parametrize(
    "filename,kwargs,compare",
    [
        (
            test_data_dir + "/section.txt",
            dict(
                status="pass",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="Cc-by-sa-4.0",
                reason="sha1",
            ),
            (
                "{{cc-by-sa-4.0}}{{iNaturalistReview |status=pass |author=Author "
                "|sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} |reviewer=iNaturalistReviewBot"
                " |reviewlicense=Cc-by-sa-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/section.txt",
            dict(
                status="fail",
                ina_author="Author",
                ina_license="Cc-by-nd-4.0",
                com_license="Cc-by-sa-4.0",
                reason="sha1",
            ),
            (
                "{{cc-by-sa-4.0}}{{iNaturalistReview |status=fail |author=Author "
                "|sourceurl=https://www.inaturalist.org/photos/11505950 "
                f"|reviewdate={date.today().isoformat()} |reviewer=iNaturalistReviewBot"
                " |reviewlicense=Cc-by-nd-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/section.txt",
            dict(
                status="fail",
                ina_author="Author",
                ina_license="Cc-by-nd-4.0",
                com_license="Cc-by-sa-4.0",
                reason="sha1",
                is_old=True,
            ),
            (
                "{{cc-by-sa-4.0}}{{iNaturalistReview |status=fail |author=Author "
                "|sourceurl=https://www.inaturalist.org/photos/11505950 "
                f"|reviewdate={date.today().isoformat()} |reviewer=iNaturalistReviewBot"
                " |reviewlicense=Cc-by-nd-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/section.txt",
            dict(status="error", reason="nodata", photo_id=None),
            (
                "{{cc-by-sa-4.0}}{{iNaturalistReview |status=error "
                f"|reviewdate={date.today().isoformat()} "
                "|reviewer=iNaturalistReviewBot |reason=nodata}}"
            ),
        ),
        (
            test_data_dir + "/section_newline.txt",
            dict(
                status="pass",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="Cc-by-sa-4.0",
                reason="sha1",
            ),
            (
                "{{cc-by-sa-4.0}}\n{{iNaturalistReview |status=pass |author=Author "
                "|sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} |reviewer=iNaturalistReviewBot"
                " |reviewlicense=Cc-by-sa-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/section_untagged.txt",
            dict(
                status="pass",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="Cc-by-sa-4.0",
                reason="sha1",
            ),
            (
                "{{cc-by-sa-4.0}}\n{{iNaturalistReview |status=pass |author=Author "
                "|sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} |reviewer=iNaturalistReviewBot"
                " |reviewlicense=Cc-by-sa-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/section_change.txt",
            dict(
                status="pass-change",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="Cc-by-4.0",
                reason="sha1",
            ),
            (
                "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass-change "
                "|author=Author |sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} "
                "|reviewer=iNaturalistReviewBot "
                "|reviewlicense=Cc-by-sa-4.0 |uploadlicense=Cc-by-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/section_change_untagged.txt",
            dict(
                status="pass-change",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="Cc-by-4.0",
                reason="sha1",
            ),
            (
                "{{Cc-by-sa-4.0}}\n{{iNaturalistReview |status=pass-change "
                "|author=Author |sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} "
                "|reviewer=iNaturalistReviewBot "
                "|reviewlicense=Cc-by-sa-4.0 |uploadlicense=Cc-by-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/section_nolic.txt",
            dict(
                status="pass-change",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="",
                reason="sha1",
            ),
            (
                "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass-change "
                "|author=Author |sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} "
                "|reviewer=iNaturalistReviewBot "
                "|reviewlicense=Cc-by-sa-4.0 |uploadlicense= |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/section_nolic_untagged.txt",
            dict(
                status="pass-change",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="",
                reason="sha1",
            ),
            (
                "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass-change "
                "|author=Author |sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} "
                "|reviewer=iNaturalistReviewBot "
                "|reviewlicense=Cc-by-sa-4.0 |uploadlicense= |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/para.txt",
            dict(
                status="pass",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="Cc-by-sa-4.0",
                reason="sha1",
            ),
            (
                "{{cc-by-sa-4.0}}{{iNaturalistReview |status=pass |author=Author "
                "|sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} |reviewer=iNaturalistReviewBot"
                " |reviewlicense=Cc-by-sa-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/para_change.txt",
            dict(
                status="pass-change",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="Cc-by-4.0",
                reason="sha1",
            ),
            (
                "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass-change "
                "|author=Author "
                "|sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} "
                "|reviewer=iNaturalistReviewBot |reviewlicense=Cc-by-sa-4.0 "
                "|uploadlicense=Cc-by-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/para_nolic.txt",
            dict(
                status="pass-change",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="",
                reason="sha1",
            ),
            (
                "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass-change "
                "|author=Author "
                "|sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} "
                "|reviewer=iNaturalistReviewBot |reviewlicense=Cc-by-sa-4.0 "
                "|uploadlicense= |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/free.txt",
            dict(
                status="pass",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="Cc-by-sa-4.0",
                reason="sha1",
            ),
            (
                "{{cc-by-sa-4.0}}\n{{iNaturalistReview |status=pass |author=Author "
                "|sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} |reviewer=iNaturalistReviewBot"
                " |reviewlicense=Cc-by-sa-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/free_change.txt",
            dict(
                status="pass-change",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="Cc-by-4.0",
                reason="sha1",
            ),
            (
                "{{Cc-by-sa-4.0}}\n{{iNaturalistReview |status=pass-change "
                "|author=Author |sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} |reviewer=iNaturalistReviewBot"
                " |reviewlicense=Cc-by-sa-4.0 |uploadlicense=Cc-by-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/self.txt",
            dict(
                status="pass",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="Cc-by-sa-4.0",
                reason="sha1",
            ),
            (
                "{{self|cc-by-sa-4.0}}{{iNaturalistReview |status=pass "
                "|author=Author |sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} |reviewer=iNaturalistReviewBot"
                " |reviewlicense=Cc-by-sa-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/self_untagged.txt",
            dict(
                status="pass",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="Cc-by-sa-4.0",
                reason="sha1",
            ),
            (
                "{{self|cc-by-sa-4.0}}\n{{iNaturalistReview |status=pass "
                "|author=Author |sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} |reviewer=iNaturalistReviewBot"
                " |reviewlicense=Cc-by-sa-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/self_change.txt",
            dict(
                status="pass-change",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="Cc-by-4.0",
                reason="sha1",
            ),
            (
                "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass-change "
                "|author=Author |sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} "
                "|reviewer=iNaturalistReviewBot "
                "|reviewlicense=Cc-by-sa-4.0 |uploadlicense=Cc-by-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/both_change.txt",
            dict(
                status="pass-change",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="Cc-by-4.0",
                reason="sha1",
            ),
            (
                "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass-change "
                "|author=Author |sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} "
                "|reviewer=iNaturalistReviewBot "
                "|reviewlicense=Cc-by-sa-4.0 |uploadlicense=Cc-by-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/wrapper_change.txt",
            dict(
                status="pass-change",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="Cc-by-4.0",
                reason="sha1",
            ),
            (
                "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass-change "
                "|author=Author |sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} "
                "|reviewer=iNaturalistReviewBot "
                "|reviewlicense=Cc-by-sa-4.0 |uploadlicense=Cc-by-4.0 |reason=sha1}}"
            ),
        ),
    ],
)
def test_update_review(filename, kwargs, compare):
    page = mock.Mock()
    with open(filename) as f:
        page.text = f.read()
    cpage = inrbot.CommonsPage(page)
    photo_id = id_tuple(type="photos", id="11505950")
    if kwargs.get("photo_id", "") is not None:
        kwargs["photo_id"] = photo_id

    cpage.archive = f"archive({kwargs['photo_id']})"
    kwargs.setdefault("no_del", False)
    kwargs.setdefault("is_old", False)
    for key, value in kwargs.items():
        setattr(cpage, key, value)

    save_page = mock.Mock()
    cpage.save_page = save_page
    cpage.update_review()

    save_page.assert_called_once
    new_text = save_page.call_args[0][0]
    assert compare in new_text
    assert "{{cc by 4.0}}" not in new_text
    assert "{{cc-by-4.0}}" not in new_text
    if kwargs.get("status", "") == "fail":
        if kwargs.get("is_old", False):
            assert inrbot.config["old_fail_tag"][:11] in new_text
        else:
            assert inrbot.config["fail_tag"][:9] in new_text


def test_update_review_broken():
    page = mock.Mock()
    page.text = "Foo"
    cpage = inrbot.CommonsPage(page)
    kwargs = dict(
        photo_id=id_tuple(type="photos", id="11505950"),
        status="pass",
        ina_author="Author",
        ina_license="Cc-by-sa-4.0",
        com_license="Cc-by-sa-4.0",
        reason="sha1",
    )
    for key, value in kwargs.items():
        setattr(cpage, key, value)
    assert cpage.update_review() is False


@pytest.mark.parametrize(
    "kwargs,compare",
    [
        (
            dict(
                status="pass",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="Cc-by-sa-4.0",
                reason="sha1",
            ),
            (
                "{{iNaturalistReview |status=pass |author=Author "
                "|sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} "
                "|reviewer=iNaturalistReviewBot |reviewlicense=Cc-by-sa-4.0 "
                "|reason=sha1}}"
            ),
        ),
        (
            dict(
                status="pass-change",
                ina_author="Author",
                ina_license="Cc-by-sa-4.0",
                com_license="Cc-by-4.0",
                reason="sha1",
            ),
            (
                "{{iNaturalistReview |status=pass-change |author=Author "
                "|sourceurl=https://www.inaturalist.org/photos/11505950 "
                "|archive=archive(https://www.inaturalist.org/photos/11505950) "
                f"|reviewdate={date.today().isoformat()} "
                "|reviewer=iNaturalistReviewBot "
                "|reviewlicense=Cc-by-sa-4.0 |uploadlicense=Cc-by-4.0 |reason=sha1}}"
            ),
        ),
        (dict(status="stop"), ""),
    ],
)
def test_make_template(kwargs, compare):
    cpage = inrbot.CommonsPage(None)
    photo_id = id_tuple(type="photos", id="11505950")
    kwargs.setdefault("photo_id", photo_id)
    kwargs.setdefault("archive", f"archive({photo_id})")
    for key, value in kwargs.items():
        setattr(cpage, key, value)
    assert cpage.make_template() == compare


@mock.patch("acnutils.check_runpage")
def test_save_page_save(runpage):
    page = mock.MagicMock()
    cpage = inrbot.CommonsPage(page)
    new_text = "new_text"
    cpage.status = "statusstatus"
    cpage.ina_license = "licensereview"

    inrbot.simulate = False
    cpage.save_page(new_text)
    assert page.text == new_text
    page.save.assert_called_once()
    summary = page.save.call_args[1]["summary"]
    assert cpage.status in summary
    assert cpage.ina_license in summary
    runpage.assert_called()


@mock.patch("acnutils.check_runpage")
def test_save_page_sim(runpage):
    page = mock.MagicMock()
    cpage = inrbot.CommonsPage(page)
    new_text = "new_text"
    cpage.status = "statusstatus"
    cpage.ina_license = "licensereview"

    inrbot.simulate = True
    cpage.save_page(new_text)
    page.save.assert_not_called()
    runpage.assert_not_called()


def test_uploader_talk():
    page = pywikibot.FilePage(inrbot.site, "File:17slemdal efn.jpg")
    cpage = inrbot.CommonsPage(page)
    user_talk = pywikibot.Page(inrbot.site, "User talk:Espen Franck-Nielsen")
    assert cpage.uploader_talk() == user_talk


@pytest.mark.parametrize("is_old", [False, True])
@mock.patch("acnutils.check_runpage")
def test_fail_warning(runpage, is_old):
    file_page = mock.MagicMock()
    cpage = inrbot.CommonsPage(file_page)
    page = mock.Mock()
    page.text = "old_text"
    page.get.return_value = page.text
    mock_get_author_talk = mock.Mock(return_value=page)
    cpage.uploader_talk = mock_get_author_talk
    cpage.ina_license = "licensereview"
    cpage.is_old = is_old

    inrbot.simulate = False
    cpage.fail_warning()

    mock_get_author_talk.assert_called_once_with()

    assert "old_text" in page.text
    if is_old:
        assert inrbot.config["old_fail_warn"][:26] in page.text
    else:
        assert inrbot.config["fail_warn"][:21] in page.text
    assert cpage.ina_license in page.text
    assert "~~~~" in page.text
    page.save.assert_called_once()

    summary = page.save.call_args[1]["summary"]
    assert "fail" in summary
    assert cpage.ina_license in summary
    runpage.assert_called()


@pytest.mark.ext_web
def test_get_observation_from_photo():
    photo_id = id_tuple(type="photos", id="58596679")
    obs_id = id_tuple(type="observations", id="36885889")
    assert inrbot.get_observation_from_photo(photo_id) == obs_id


@pytest.mark.parametrize(
    "conf,expected",
    [
        ({"old_fail": False}, False),
        ({"old_fail": True, "old_fail_age": 180}, False),
        ({"old_fail": True, "old_fail_age": 10}, True),
    ],
)
def test_file_is_old(conf, expected):
    mock_page = mock.Mock()
    mock_page.latest_file_info.timestamp = datetime.datetime.now() - datetime.timedelta(
        days=60
    )
    cpage = inrbot.CommonsPage(mock_page)
    cpage.status = "fail"
    with mock.patch.dict("inrbot.config", conf):
        result = cpage.is_old
    assert result is expected


@mock.patch("acnutils.check_runpage")
def test_review_file_checkrun(runpage):
    cpage = inrbot.CommonsPage(mock.Mock(spec=pywikibot.FilePage))
    mock_check = mock.MagicMock(return_value=False)
    mock_update = mock.MagicMock()
    with mock.patch.object(cpage, "check_can_run", mock_check):
        with mock.patch.object(cpage, "update_review", mock_update):
            assert cpage.review_file() is None
    mock_check.assert_called_once()
    mock_update.assert_not_called()
    runpage.assert_called()


@mock.patch("acnutils.check_runpage")
def test_review_file_stop(runpage):
    cpage = inrbot.CommonsPage(mock.Mock(spec=pywikibot.FilePage))
    mock_review = mock.Mock()
    with mock.patch.multiple(
        cpage,
        check_can_run=mock.Mock(return_value=True),
        check_stop_cats=mock.Mock(side_effect=inrbot.StopReview("")),
        update_review=mock_review,
    ):
        cpage.review_file()
    assert cpage.status == "stop"
    mock_review.assert_called_once()
    runpage.assert_called()


@pytest.mark.parametrize(
    "exc,reason",
    [(inrbot.ProcessingError("foo", ""), "foo"), (TypeError, "TypeError()")],
)
@mock.patch("acnutils.check_runpage")
def test_review_file_error(runpage, exc, reason):
    mock_page = mock.Mock(spec=pywikibot.FilePage, text="{{iNaturalistreview}}")
    cpage = inrbot.CommonsPage(mock_page)
    mock_review = mock.Mock()
    with mock.patch.multiple(
        cpage,
        check_can_run=mock.Mock(return_value=True),
        check_stop_cats=mock.DEFAULT,
        update_review=mock_review,
        find_ina_id=mock.Mock(side_effect=exc),
    ):
        cpage.review_file()
    assert cpage.status == "error"
    assert cpage.reason == reason
    mock_review.assert_called_once()
    runpage.assert_called()


@mock.patch("acnutils.check_runpage")
def test_review_file_error_untagged(runpage):
    exc = inrbot.ProcessingError("notfound", "")
    reason = "notfound"
    mock_page = mock.Mock(spec=pywikibot.FilePage, text="{{iNaturalistreview}}")
    cpage = inrbot.CommonsPage(mock_page)
    mock_review = mock.Mock()
    log_untagged_error = mock.Mock()
    with mock.patch.multiple(
        cpage,
        check_can_run=mock.Mock(return_value=True),
        check_stop_cats=mock.DEFAULT,
        update_review=mock_review,
        find_ina_id=mock.Mock(side_effect=exc),
        check_has_template=mock.Mock(return_value=False),
        log_untagged_error=log_untagged_error,
    ):
        cpage.review_file()
    assert cpage.status == "error"
    assert cpage.reason == reason
    mock_review.assert_not_called()
    log_untagged_error.assert_called_once()
    runpage.assert_called()


@mock.patch("acnutils.check_runpage")
def test_review_file_interrupt(runpage):
    cpage = inrbot.CommonsPage(mock.Mock(spec=pywikibot.FilePage))
    mock_review = mock.Mock()
    with mock.patch.multiple(
        cpage,
        check_can_run=mock.Mock(return_value=True),
        check_stop_cats=mock.DEFAULT,
        update_review=mock_review,
        find_ina_id=mock.Mock(side_effect=KeyboardInterrupt),
    ):
        with pytest.raises(KeyboardInterrupt):
            cpage.review_file()
    mock_review.assert_not_called()
    runpage.assert_called()


@pytest.mark.parametrize(
    "reviewed,status,no_del,expected",
    [
        (True, "fail", False, True),
        (False, "fail", False, False),
        (True, "error", False, False),
        (True, "fail", True, False),
    ],
)
@mock.patch("acnutils.check_runpage")
def test_review_file_warn(runpage, reviewed, status, no_del, expected):
    mock_page = mock.Mock(spec=pywikibot.FilePage, text="{{iNaturalistreview}}")
    cpage = inrbot.CommonsPage(mock_page)
    cpage.no_del = no_del
    cpage.status = status
    mock_review = mock.Mock(return_value=reviewed)
    mock_warn = mock.Mock()
    with mock.patch.multiple(
        cpage,
        check_can_run=mock.Mock(return_value=True),
        update_review=mock_review,
        fail_warning=mock_warn,
        find_ina_id=mock.Mock(return_value=(None, None)),
        check_stop_cats=mock.DEFAULT,
        find_photo_in_obs=mock.DEFAULT,
        compare_licenses=mock.DEFAULT,
        get_ina_author=mock.DEFAULT,
        get_old_archive=mock.DEFAULT,
    ):
        cpage.review_file()
    mock_review.assert_called_once()
    assert mock_warn.called is expected
    runpage.assert_called()


def test_main_auto_total():
    mock_cpage = mock.MagicMock()
    review_file = mock.MagicMock()
    mock_cpage.return_value.review_file = review_file
    sleep = mock.MagicMock()
    files_to_check = mock.MagicMock(return_value=range(0, 10))
    untagged_files_to_check = mock.MagicMock(return_value=range(0, 10))
    total = 4

    with mock.patch("inrbot.CommonsPage", mock_cpage):
        with mock.patch("time.sleep", sleep):
            with mock.patch("inrbot.files_to_check", files_to_check):
                with mock.patch(
                    "inrbot.untagged_files_to_check", untagged_files_to_check
                ):
                    with mock.patch("pywikibot.FilePage", lambda arg: arg):
                        inrbot.main(total=total)

    assert review_file.call_count == total


def test_main_auto_end():
    mock_cpage = mock.MagicMock()
    review_file = mock.MagicMock()
    mock_cpage.return_value.review_file = review_file
    sleep = mock.MagicMock()
    files_to_check = mock.MagicMock(return_value=range(0, 3))
    untagged_files_to_check = mock.MagicMock(return_value=range(0, 3))
    total = 10

    with mock.patch("inrbot.CommonsPage", mock_cpage):
        with mock.patch("time.sleep", sleep):
            with mock.patch("inrbot.files_to_check", files_to_check):
                with mock.patch(
                    "inrbot.untagged_files_to_check", untagged_files_to_check
                ):
                    with mock.patch("pywikibot.FilePage", lambda arg: arg):
                        inrbot.main(total=total)

    assert review_file.call_count == total


def test_main_auto_blocked():
    # Runpage fails and actually being blocked should stop the bot.
    mock_cpage = mock.MagicMock()
    review_file = mock.MagicMock()
    review_file.side_effect = acnutils.RunpageError("Runpage is false!")
    mock_cpage.return_value.review_file = review_file
    sleep = mock.MagicMock()
    files_to_check = mock.MagicMock(return_value=range(0, 10))

    with mock.patch("inrbot.CommonsPage", mock_cpage):
        with mock.patch("time.sleep", sleep):
            with mock.patch("inrbot.files_to_check", files_to_check):
                with mock.patch("pywikibot.FilePage", lambda arg: arg):
                    with pytest.raises(acnutils.RunpageError):
                        inrbot.main(total=1)

    sleep.assert_not_called()


def test_main_auto_exception_continue():
    # Other exceptions can be handled
    mock_cpage = mock.MagicMock()
    review_file = mock.MagicMock()
    review_file.side_effect = [ValueError, None, None]
    mock_cpage.return_value.review_file = review_file
    sleep = mock.MagicMock()
    files_to_check = mock.MagicMock(return_value=range(0, 10))
    total = 3

    with mock.patch("inrbot.CommonsPage", mock_cpage):
        with mock.patch("time.sleep", sleep):
            with mock.patch("inrbot.files_to_check", files_to_check):
                with mock.patch("pywikibot.FilePage", lambda arg: arg):
                    inrbot.main(total=total)

    assert review_file.call_count == total


def test_main_auto_exception_stop():
    # Other exceptions can be handled
    mock_cpage = mock.MagicMock()
    review_file = mock.MagicMock()
    review_file.side_effect = ValueError
    mock_cpage.return_value.review_file = review_file
    sleep = mock.MagicMock()
    files_to_check = mock.MagicMock(return_value=range(0, 10))
    total = 2

    with mock.patch("inrbot.CommonsPage", mock_cpage):
        with mock.patch("time.sleep", sleep):
            with mock.patch("inrbot.files_to_check", files_to_check):
                with mock.patch("pywikibot.FilePage", lambda arg: arg):
                    with pytest.raises(ValueError):
                        inrbot.main(total=total)

    assert review_file.call_count == total


def test_main_single():
    mock_cpage = mock.MagicMock()
    page = mock.MagicMock()

    with mock.patch("inrbot.CommonsPage", mock_cpage):
        with mock.patch("pywikibot.FilePage", lambda arg: arg):
            inrbot.main(page=page)

    mock_cpage.assert_called_once_with(page)

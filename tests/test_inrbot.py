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
import pywikibot
import sys
import os

_work_dir_ = os.path.dirname(__file__)
sys.path.append(os.path.realpath(_work_dir_ + "/../src"))

import inrbot  # noqa: E402
import utils  # noqa: E402

test_data_dir = os.path.join(_work_dir_, "testdata")
id_tuple = inrbot.iNaturalistID


def test_check_can_run_skip():
    page = pywikibot.Page(inrbot.site, "File:Male.svg")
    assert type(inrbot.skip) is set
    inrbot.skip.add("File:Male.svg")
    inrbot.check_can_run(page)
    inrbot.skip.remove("File:Male.svg")


def test_check_can_run_protected():
    page = pywikibot.Page(inrbot.site, "Main Page")
    assert not inrbot.check_can_run(page)


def test_check_can_run_exclusion():
    page = pywikibot.Page(inrbot.site, "File:Male.svg")
    assert not inrbot.check_can_run(page)


def test_check_can_run_template():
    page = mock.MagicMock()
    page.text = "{{iNaturalistreview}}"
    assert inrbot.check_can_run(page)


def test_check_can_run_no_template():
    page = mock.MagicMock()
    page.text = "foo"
    assert not inrbot.check_can_run(page)


def test_check_can_run_paras():
    page = mock.MagicMock()
    page.text = "{{iNaturalistreview|status=error}}"
    assert not inrbot.check_can_run(page)


def test_check_runpage_run():
    page = mock.MagicMock()
    page.return_value.text = "<!-- Set to False to stop bot. -->\nTrue"

    with mock.patch("pywikibot.Page", page):
        utils.check_runpage(inrbot.site)


def test_check_runpage_stop():
    page = mock.MagicMock()
    page.return_value.text = "<!-- Set to False to stop bot. -->\nFalse"

    with pytest.raises(pywikibot.UserBlocked):
        with mock.patch("pywikibot.Page", page):
            utils.check_runpage(inrbot.site)


def test_check_runpage_stop_anything():
    page = mock.MagicMock()
    page.return_value.text = "Stop!"

    with pytest.raises(pywikibot.UserBlocked):
        with mock.patch("pywikibot.Page", page):
            utils.check_runpage(inrbot.site)


def test_check_runpage_stop_blank():
    page = mock.MagicMock()
    page.return_value.text = ""

    with pytest.raises(pywikibot.UserBlocked):
        with mock.patch("pywikibot.Page", page):
            utils.check_runpage(inrbot.site)


def test_check_runpage_override():
    page = mock.MagicMock()
    page.return_value.text = "<!-- Set to False to stop bot. -->\nFalse"

    with mock.patch("pywikibot.Page", page):
        utils.check_runpage(inrbot.site, override=True)


def test_files_to_check():
    assert inspect.isgeneratorfunction(inrbot.files_to_check)


def test_find_ina_id():
    page = mock.MagicMock()
    extlinks = [
        "http://example.com",
        "https://www.inaturalist.org/observations/15059501",
    ]
    page.extlinks.return_value = extlinks
    ina_id = inrbot.find_ina_id(page)
    compare = id_tuple(id="15059501", type="observations")
    assert ina_id[0] == compare


def test_find_ina_id_none():
    page = mock.MagicMock()
    extlinks = [
        "http://example.com",
    ]
    page.extlinks.return_value = extlinks
    ina_id = inrbot.find_ina_id(page)
    assert ina_id == (None, None)


def test_find_ina_id_nourls():
    page = mock.MagicMock()
    extlinks = []
    page.extlinks.return_value = extlinks
    ina_id = inrbot.find_ina_id(page)
    assert ina_id == (None, None)


def test_find_ina_id_multiple():
    page = mock.MagicMock()
    extlinks = [
        "https://www.inaturalist.org/photos/12345",
        "https://www.inaturalist.org/observations/15059501",
    ]
    page.extlinks.return_value = extlinks
    ina_id = inrbot.find_ina_id(page)
    obs = id_tuple(id="15059501", type="observations")
    pho = id_tuple(id="12345", type="photos")
    assert ina_id == (obs, pho)


def test_find_ina_id_photos():
    page = mock.MagicMock()
    extlinks = [
        "http://example.com",
        "https://www.inaturalist.org/photos/12345",
    ]
    page.extlinks.return_value = extlinks
    ina_id = inrbot.find_ina_id(page)
    compare = id_tuple(id="12345", type="photos")
    assert ina_id[1] == compare


@pytest.mark.ext_web
def test_get_ina_data_observation():
    ina_id = id_tuple(id="36885889", type="observations")
    response = inrbot.get_ina_data(ina_id)
    assert response
    assert type(response) is dict


def test_get_ina_data_wrong_endpoint():
    ina_id = id_tuple(id="anticompositenumber", type="people")
    response = inrbot.get_ina_data(ina_id)
    assert response is None


def test_get_ina_data_bad_data():
    ina_id = id_tuple(id="36885889", type="observations")
    mock_session = mock.MagicMock()
    mock_session.get.return_value.json.return_value = {"total_results": 1}
    with mock.patch("inrbot.session", mock_session):
        response = inrbot.get_ina_data(ina_id)

    assert response is None


def test_get_ina_data_wrong_number():
    ina_id = id_tuple(id="36885889", type="observations")
    mock_session = mock.MagicMock()
    mock_session.get.return_value.json.return_value = {"total_results": 2}
    with mock.patch("inrbot.session", mock_session):
        response = inrbot.get_ina_data(ina_id)

    assert response is None


def test_get_ina_data_error():
    ina_id = id_tuple(id="36885889", type="observations")
    mock_session = mock.MagicMock()
    mock_session.get.side_effect = requests.exceptions.HTTPError
    with mock.patch("inrbot.session", mock_session):
        response = inrbot.get_ina_data(ina_id)

    assert response is None


@pytest.mark.ext_web
def test_find_photo_in_obs():
    page = mock.MagicMock()
    page.latest_file_info.sha1 = "a80ef8a886c3deeeded624856fb83d269dda1683"
    obs_id = id_tuple(id="36885821", type="observations")
    ina_data = inrbot.get_ina_data(obs_id)

    photo, found = inrbot.find_photo_in_obs(page, obs_id, ina_data)
    assert found == "sha1"
    assert photo._replace(url="") == id_tuple(id="58381754", type="photos")


@pytest.mark.ext_web
def test_find_photo_in_obs_ssim_pass():
    page = pywikibot.FilePage(inrbot.site, "File:Acomys subspinosus 15087534.jpg")
    obs_id = id_tuple(id="10783720", type="observations")
    ina_data = inrbot.get_ina_data(obs_id)
    mock_config = {"use_ssim": True}
    from ssim import compute_ssim

    inrbot.compute_ssim = compute_ssim
    with mock.patch("inrbot.compare_photo_hashes", return_value=False):
        with mock.patch.dict("inrbot.config", mock_config):
            photo, found = inrbot.find_photo_in_obs(page, obs_id, ina_data)

    assert found.startswith("ssim")
    assert photo._replace(url="") == id_tuple(id="15087534", type="photos")


@pytest.mark.ext_web
def test_find_photo_in_obs_ssim_fail():
    page = pywikibot.FilePage(inrbot.site, "File:Acomys subspinosus 15087534.jpg")
    obs_id = id_tuple(id="10783720", type="observations")
    ina_data = inrbot.get_ina_data(obs_id)
    thumb_url = page.get_file_url(url_width=340)
    mock_url = mock.Mock(return_value=thumb_url)
    page.get_file_url = mock_url
    mock_config = {"use_ssim": True}
    from ssim import compute_ssim

    inrbot.compute_ssim = compute_ssim
    with mock.patch("inrbot.compare_photo_hashes", return_value=False):
        with mock.patch.dict("inrbot.config", mock_config):
            photo, found = inrbot.find_photo_in_obs(page, obs_id, ina_data)

    assert found == "notmatching"
    assert photo is None


def test_find_photo_in_obs_notfound():
    page = mock.MagicMock()
    obs_id = mock.MagicMock()
    ina_data = {"photos": []}

    photo, found = inrbot.find_photo_in_obs(page, obs_id, ina_data)
    assert photo is None
    assert found == "notfound"


@pytest.mark.ext_web
def test_find_photo_in_obs_notmatching():
    page = mock.MagicMock()
    page.latest_file_info.sha1 = "foo"
    obs_id = id_tuple(id="36885821", type="observations")
    ina_data = inrbot.get_ina_data(obs_id)

    photo, found = inrbot.find_photo_in_obs(page, obs_id, ina_data)
    assert photo is None
    assert found == "notmatching"


@pytest.mark.ext_web
def test_find_photo_in_obs_ignore():
    page = mock.MagicMock()
    mock_compare = mock.Mock(return_value=False)
    mock_config = {"use_ssim": False}
    obs_id = id_tuple(id="36885889", type="observations")
    photo_id = id_tuple(id="12345", type="photos")
    ina_data = inrbot.get_ina_data(obs_id)

    with mock.patch.dict("inrbot.config", mock_config):
        with mock.patch("inrbot.compare_photo_hashes", mock_compare):
            photo, found = inrbot.find_photo_in_obs(
                page, obs_id, ina_data, raw_photo_id=photo_id
            )
    assert mock_compare.call_count == 3


def test_find_photo_in_obs_photo():
    page = mock.MagicMock()
    mock_compare = mock.Mock(return_value=False)
    mock_config = {"use_ssim": False}
    obs_id = id_tuple(id="36885889", type="observations")
    photo_id = id_tuple(id="58596679", type="photos")
    ina_data = inrbot.get_ina_data(obs_id)

    with mock.patch.dict("inrbot.config", mock_config):
        with mock.patch("inrbot.compare_photo_hashes", mock_compare):
            photo, found = inrbot.find_photo_in_obs(
                page, obs_id, ina_data, raw_photo_id=photo_id
            )
    assert mock_compare.call_count == 1


def test_find_ina_license():
    with open(test_data_dir + "/ina_response.json") as f:
        ina_data = json.load(f)
    photo = id_tuple(id="22483426", type="photos")
    assert inrbot.find_ina_license(ina_data, photo) == "Cc-by-4.0"


def test_find_ina_license_fail():
    with open(test_data_dir + "/ina_response.json") as f:
        ina_data = json.load(f)
    photo = id_tuple(id="12345", type="photos")
    assert inrbot.find_ina_license(ina_data, photo) == ""


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
    assert license == ""


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


@pytest.mark.parametrize(
    "filename,kwargs,compare",
    [
        (
            test_data_dir + "/section.txt",
            dict(
                status="pass",
                author="Author",
                review_license="Cc-by-sa-4.0",
                upload_license="Cc-by-sa-4.0",
                reason="sha1",
            ),
            (
                "{{cc-by-sa-4.0}}{{iNaturalistReview |status=pass |author=Author "
                "|sourceurl=https://www.inaturalist.org/photos/11505950 "
                f"|reviewdate={date.today().isoformat()} |reviewer=iNaturalistReviewBot"
                " |reviewlicense=Cc-by-sa-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/section.txt",
            dict(
                status="fail",
                author="Author",
                review_license="Cc-by-nd-4.0",
                upload_license="Cc-by-sa-4.0",
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
                author="Author",
                review_license="Cc-by-nd-4.0",
                upload_license="Cc-by-sa-4.0",
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
                author="Author",
                review_license="Cc-by-sa-4.0",
                upload_license="Cc-by-sa-4.0",
                reason="sha1",
            ),
            (
                "{{cc-by-sa-4.0}}\n{{iNaturalistReview |status=pass |author=Author "
                "|sourceurl=https://www.inaturalist.org/photos/11505950 "
                f"|reviewdate={date.today().isoformat()} |reviewer=iNaturalistReviewBot"
                " |reviewlicense=Cc-by-sa-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/section_change.txt",
            dict(
                status="pass-change",
                author="Author",
                review_license="Cc-by-sa-4.0",
                upload_license="Cc-by-4.0",
                reason="sha1",
            ),
            (
                "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass-change "
                "|author=Author |sourceurl=https://www.inaturalist.org/photos/11505950 "
                f"|reviewdate={date.today().isoformat()} "
                "|reviewer=iNaturalistReviewBot "
                "|reviewlicense=Cc-by-sa-4.0 |uploadlicense=Cc-by-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/para.txt",
            dict(
                status="pass",
                author="Author",
                review_license="Cc-by-sa-4.0",
                upload_license="Cc-by-sa-4.0",
                reason="sha1",
            ),
            (
                "{{cc-by-sa-4.0}}{{iNaturalistReview |status=pass |author=Author "
                "|sourceurl=https://www.inaturalist.org/photos/11505950 "
                f"|reviewdate={date.today().isoformat()} |reviewer=iNaturalistReviewBot"
                " |reviewlicense=Cc-by-sa-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/para_change.txt",
            dict(
                status="pass-change",
                author="Author",
                review_license="Cc-by-sa-4.0",
                upload_license="Cc-by-4.0",
                reason="sha1",
            ),
            (
                "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass-change "
                "|author=Author "
                "|sourceurl=https://www.inaturalist.org/photos/11505950 "
                f"|reviewdate={date.today().isoformat()} "
                "|reviewer=iNaturalistReviewBot |reviewlicense=Cc-by-sa-4.0 "
                "|uploadlicense=Cc-by-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/free.txt",
            dict(
                status="pass",
                author="Author",
                review_license="Cc-by-sa-4.0",
                upload_license="Cc-by-sa-4.0",
                reason="sha1",
            ),
            (
                "{{cc-by-sa-4.0}}\n{{iNaturalistReview |status=pass |author=Author "
                "|sourceurl=https://www.inaturalist.org/photos/11505950 "
                f"|reviewdate={date.today().isoformat()} |reviewer=iNaturalistReviewBot"
                " |reviewlicense=Cc-by-sa-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/free_change.txt",
            dict(
                status="pass-change",
                author="Author",
                review_license="Cc-by-sa-4.0",
                upload_license="Cc-by-4.0",
                reason="sha1",
            ),
            (
                "{{Cc-by-sa-4.0}}\n{{iNaturalistReview |status=pass-change "
                "|author=Author |sourceurl=https://www.inaturalist.org/photos/11505950 "
                f"|reviewdate={date.today().isoformat()} |reviewer=iNaturalistReviewBot"
                " |reviewlicense=Cc-by-sa-4.0 |uploadlicense=Cc-by-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/self.txt",
            dict(
                status="pass",
                author="Author",
                review_license="Cc-by-sa-4.0",
                upload_license="Cc-by-sa-4.0",
                reason="sha1",
            ),
            (
                "{{self|cc-by-sa-4.0}}{{iNaturalistReview |status=pass "
                "|author=Author |sourceurl=https://www.inaturalist.org/photos/11505950 "
                f"|reviewdate={date.today().isoformat()} |reviewer=iNaturalistReviewBot"
                " |reviewlicense=Cc-by-sa-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/self_change.txt",
            dict(
                status="pass-change",
                author="Author",
                review_license="Cc-by-sa-4.0",
                upload_license="Cc-by-4.0",
                reason="sha1",
            ),
            (
                "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass-change "
                "|author=Author |sourceurl=https://www.inaturalist.org/photos/11505950 "
                f"|reviewdate={date.today().isoformat()} "
                "|reviewer=iNaturalistReviewBot "
                "|reviewlicense=Cc-by-sa-4.0 |uploadlicense=Cc-by-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/both_change.txt",
            dict(
                status="pass-change",
                author="Author",
                review_license="Cc-by-sa-4.0",
                upload_license="Cc-by-4.0",
                reason="sha1",
            ),
            (
                "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass-change "
                "|author=Author |sourceurl=https://www.inaturalist.org/photos/11505950 "
                f"|reviewdate={date.today().isoformat()} "
                "|reviewer=iNaturalistReviewBot "
                "|reviewlicense=Cc-by-sa-4.0 |uploadlicense=Cc-by-4.0 |reason=sha1}}"
            ),
        ),
        (
            test_data_dir + "/wrapper_change.txt",
            dict(
                status="pass-change",
                author="Author",
                review_license="Cc-by-sa-4.0",
                upload_license="Cc-by-4.0",
                reason="sha1",
            ),
            (
                "{{Cc-by-sa-4.0}}{{iNaturalistReview |status=pass-change "
                "|author=Author |sourceurl=https://www.inaturalist.org/photos/11505950 "
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
    photo_id = id_tuple(type="photos", id="11505950")
    if kwargs.get("photo_id", "") is not None:
        kwargs["photo_id"] = photo_id

    save_page = mock.Mock()
    with mock.patch("inrbot.save_page", save_page):
        inrbot.update_review(page, **kwargs)

    save_page.assert_called_once
    new_text = save_page.call_args[0][1]
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
    photo_id = id_tuple(type="photos", id="11505950")
    result = inrbot.update_review(
        page,
        photo_id,
        status="pass",
        author="Author",
        review_license="Cc-by-sa-4.0",
        upload_license="Cc-by-sa-4.0",
        reason="sha1",
    )
    assert result is False


def test_make_template():
    photo_id = id_tuple(type="photos", id="11505950")
    template = inrbot.make_template(
        photo_id,
        status="pass",
        author="Author",
        review_license="Cc-by-sa-4.0",
        upload_license="Cc-by-sa-4.0",
        reason="sha1",
    )
    compare = (
        "{{iNaturalistReview |status=pass |author=Author "
        "|sourceurl=https://www.inaturalist.org/photos/11505950 "
        f"|reviewdate={date.today().isoformat()} "
        "|reviewer=iNaturalistReviewBot |reviewlicense=Cc-by-sa-4.0 |reason=sha1}}"
    )
    assert str(template) == compare


def test_make_template_change():
    photo_id = id_tuple(type="photos", id="11505950")
    template = inrbot.make_template(
        photo_id,
        status="pass-change",
        author="Author",
        review_license="Cc-by-sa-4.0",
        upload_license="Cc-by-4.0",
        reason="sha1",
    )
    compare = (
        "{{iNaturalistReview |status=pass-change |author=Author "
        "|sourceurl=https://www.inaturalist.org/photos/11505950 "
        f"|reviewdate={date.today().isoformat()} "
        "|reviewer=iNaturalistReviewBot "
        "|reviewlicense=Cc-by-sa-4.0 |uploadlicense=Cc-by-4.0 |reason=sha1}}"
    )
    assert str(template) == compare


def test_save_page_save():
    page = mock.MagicMock()
    new_text = "new_text"
    status = "statusstatus"
    review_license = "licensereview"

    inrbot.simulate = False
    inrbot.save_page(page, new_text, status, review_license)
    assert page.text == new_text
    page.save.assert_called_once()
    summary = page.save.call_args[1]["summary"]
    assert status in summary
    assert review_license in summary


def test_save_page_sim():
    page = mock.MagicMock()
    new_text = "new_text"
    status = "statusstatus"
    review_license = "licensereview"

    inrbot.simulate = True
    inrbot.save_page(page, new_text, status, review_license)
    page.save.assert_not_called()


def test_get_author_talk():
    page = pywikibot.FilePage(inrbot.site, "File:17slemdal efn.jpg")
    user_talk = pywikibot.Page(inrbot.site, "User talk:Espen Franck-Nielsen")
    assert inrbot.get_author_talk(page) == user_talk


@pytest.mark.parametrize("is_old", [False, True])
def test_fail_warning(is_old):
    file_page = mock.MagicMock()
    page = mock.Mock()
    page.text = "old_text"
    page.get.return_value = page.text
    mock_get_author_talk = mock.Mock(return_value=page)
    review_license = "licensereview"

    inrbot.simulate = False
    with mock.patch("inrbot.get_author_talk", mock_get_author_talk):
        inrbot.fail_warning(file_page, review_license, is_old)

    mock_get_author_talk.assert_called_once_with(file_page)

    assert "old_text" in page.text
    if is_old:
        assert inrbot.config["old_fail_warn"][:26] in page.text
    else:
        assert inrbot.config["fail_warn"][:21] in page.text
    assert review_license in page.text
    assert "~~~~" in page.text
    page.save.assert_called_once()

    summary = page.save.call_args[1]["summary"]
    assert "fail" in summary
    assert review_license in summary


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
    with mock.patch.dict("inrbot.config", conf):
        result = inrbot.file_is_old(mock_page)
    assert result is expected


def test_main_auto_total():
    review_file = mock.MagicMock()
    sleep = mock.MagicMock()
    files_to_check = mock.MagicMock(return_value=range(0, 10))
    total = 4

    with mock.patch("inrbot.review_file", review_file):
        with mock.patch("time.sleep", sleep):
            with mock.patch("inrbot.files_to_check", files_to_check):
                inrbot.main(total=total)

    assert review_file.call_count == total


def test_main_auto_end():
    review_file = mock.MagicMock()
    sleep = mock.MagicMock()
    files_to_check = mock.MagicMock(return_value=range(0, 3))
    total = 7

    with mock.patch("inrbot.review_file", review_file):
        with mock.patch("time.sleep", sleep):
            with mock.patch("inrbot.files_to_check", files_to_check):
                inrbot.main(total=total)

    assert review_file.call_count == total


def test_main_auto_blocked():
    # Runpage fails and actually being blocked should stop the bot.
    review_file = mock.MagicMock()
    review_file.side_effect = pywikibot.UserBlocked("Runpage is false!")
    sleep = mock.MagicMock()
    files_to_check = mock.MagicMock(return_value=range(0, 10))

    with mock.patch("inrbot.review_file", review_file):
        with mock.patch("time.sleep", sleep):
            with mock.patch("inrbot.files_to_check", files_to_check):
                with pytest.raises(pywikibot.UserBlocked):
                    inrbot.main(total=1)

    sleep.assert_not_called()


def test_main_auto_exception():
    # Other exceptions can be handled
    review_file = mock.MagicMock()
    review_file.side_effect = ValueError
    sleep = mock.MagicMock()
    files_to_check = mock.MagicMock(return_value=range(0, 10))
    total = 2

    with mock.patch("inrbot.review_file", review_file):
        with mock.patch("time.sleep", sleep):
            with mock.patch("inrbot.files_to_check", files_to_check):
                inrbot.main(total=total)

    assert review_file.call_count == total


def test_main_single():
    review_file = mock.MagicMock()
    page = mock.MagicMock()

    with mock.patch("inrbot.review_file", review_file):
        inrbot.main(page=page)

    review_file.assert_called_once_with(page)

# iNaturalistReviewer
![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/AntiCompositeNumber/iNaturalistReviewer/pythonapp.yml?branch=master)
![Uptime Robot status](https://img.shields.io/uptimerobot/status/m784049619-0b897b81ddd538c8962c1172?label=runpage)
[![Coverage Status](https://coveralls.io/repos/github/AntiCompositeNumber/iNaturalistReviewer/badge.svg?branch=master)](https://coveralls.io/github/AntiCompositeNumber/iNaturalistReviewer?branch=master)
![Python version 3.11](https://img.shields.io/badge/python-v3.11-blue)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Automatic iNaturalist reviewer for Commons.

## Usage
### inrbot
One-shot:
- `inrbot.py --file File:Example.png` Runs the bot on File:Example.png only.

Bot mode:
- `inrbot.py --auto` Runs the bot continuously.
- `inrbot.py --auto --total 5` Runs the bot on 5 files.

Optional args:
- `--simulate` Prints the wikitext output instead of writing to the wiki.
- `--ignore-runpage` Skips the on-wiki runpage check for use in development. Sets `--simulate` unless overridden with `--no-simulate`.
- `-h --help` Prints help information
- `--version` Prints version information

### inrcli
inrcli is a modified interface to inrbot that makes manual reviewing of files easier. You will be prompted to manually input the correct photo URL or to re-attempt automatic detection. Confirmation of the license status is usually handled automatically, unless there is an archived copy in the Wayback Machine that needs to be manually reviewed. To skip a file, press Ctrl+C.

Reviewing specific files:
- `inrcli.py File:Example.png` Reviews File:Example.png only.
- `inrcli.py File:Example.png --url https://www.inaturalist.org/photos/12345` Reviews File:Example.png with `https://www.inaturalist.org/photos/12345` as the iNaturalist source URL.
- `inrcli.py ask` Repeatedly prompts for files to review.

Reviewing previously-reviewed files:
- `inrcli.py auto` Review files from https://commons.wikimedia.org/wiki/Category:INaturalist_images_needing_human_review
- `inrcli.py errors` Review files from https://commons.wikimedia.org/wiki/User:INaturalistReviewBot/untagged_error_log

## Deployment
This bot runs on Toolforge as `inaturalistreviewer` with the `python3.11` Kubernetes container.
It uses the `toolforge jobs` configuration in jobs.yaml and assumes that there is a python 3.11 virtualenv in `/data/project/inaturalistreviewer/iNaturalistReviewer/venv/`.

To stop the bot:
`toolforge jobs delete inrbot`

To start the bot in automatic mode:
`toolforge jobs load ~/iNaturalistReviewer/jobs.yaml --job inrbot`

To get the pod status:
`toolforge jobs list`

### Updating the bot
With only code changes:
```console
$ cd iNaturalistReviewer
$ git pull
$ toolforge jobs restart inrbot
```

With code changes and/or dependency updates:
```console
$ cd iNaturalistReviewer
$ git pull
$ toolforge jobs load jobs.yaml
```

## Commons intergration
The bot is controlled by a [runpage on Commons](https://commons.wikimedia.org/wiki/User:INaturalistReviewBot/Run). If the runpage does not end with True, the bot will stop cleanly. Blocking the bot will also stop it from running. Using the runpage is preferred as it is faster and easier for everyone involved.

The bot looks for images in [Category:iNaturalist review needed](https://commons.wikimedia.org/wiki/Category:INaturalist_review_needed) that transclude {{[iNaturalistreview](https://commons.wikimedia.org/wiki/Template:INaturalistreview)}}. It will also attempt to review files that are likely sourced to iNaturalist that have not yet been tagged with the template.

If the bot can not automatically determine the license status, it sets `|status=error` with the review date and the reviewer parameters. Files that were not previously tagged will instead be listed at [User:INaturalistReviewBot/untagged error log](https://commons.wikimedia.org/wiki/User:INaturalistReviewBot/untagged_error_log) to avoid spurious tags.

If the bot determines that the image is freely licensed on iNaturalist, it sets `|status=pass` with the author, source URL, review date, reviewer, and review license parameters.

If the bot determines that the image is freely licensed on iNaturalist but the Commons license is wrong, it will change the license template on Commons and set `|status=pass-change` with the author, source URL, review date, reviewer, review license, and upload license parameters.

If the bot determines that the image is under a non-free license on iNaturalist, it will add `{{copyvio|Bot license review NOT PASSED: iNaturalist author is using <review_license>` to the top of the file and set `|status=fail` with the author, source url, review date, reviewer, and review license parameters. Older files will instead be tagged with `{{No permission since}}` to allow the uploader a chance to correct the license.

### |reason= parameter
The bot will add a `|reason=` parameter when it tags files. This parameter is not read by the template, and exists mostly for debugging.
- `nourl`: No iNaturalist /photos/ or /observations/ URL was found on the file page.
- `apierr`: No data was recieved from the iNaturalist API. This usually indicates a problem with how the API is called, not the API itself.
- `notmatching`: No photo on iNaturalist was found that matched the Commons file. That usually means the Commons file has been modified or the URL is wrong.
- `sha1`: The Commons file was matched to an iNaturalist photo using a SHA-1 hash. Errors with this reason typically indicate a problem comparing the licenses.
- `phash`: The Commons file was matched to an iNaturalist photo based on a [perceptual hashing algorithm](https://github.com/JohannesBuchner/imagehash).
- `crop_resistant_hash` The Commons file was matched to an iNaturalist photo using a [crop-resistant hashing algorithm](https://github.com/JohannesBuchner/imagehash).
- `manual`: The Commons file was manually matched to an iNaturalist photo using inrcli.
- Other Python exceptions when reviewing fails in an *interesting* way.

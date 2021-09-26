# iNaturalistReviewer
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/AntiCompositeNumber/iNaturalistReviewer/Python%20application)
![Uptime Robot status](https://img.shields.io/uptimerobot/status/m784049619-0b897b81ddd538c8962c1172?label=runpage)
![GitHub issues by-label](https://img.shields.io/github/issues/AntiCompositeNumber/iNaturalistReviewer/prod-error)
[![Coverage Status](https://coveralls.io/repos/github/AntiCompositeNumber/iNaturalistReviewer/badge.svg?branch=master)](https://coveralls.io/github/AntiCompositeNumber/iNaturalistReviewer?branch=master)
![Python version 3.9](https://img.shields.io/badge/python-v3.9-blue)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Automatic iNaturalist reviewer for Commons.

## Usage
One-shot:
`inrbot.py --file File:Example.png` Runs the bot on File:Example.png only.

Bot mode:
`inrbot.py --auto` Runs the bot continuously.
`inrbot.py --auto --total 5` Runs the bot on 5 files.

Optional args:
`--simulate` Prints the wikitext output instead of writing to the wiki.
`--ignore-runpage` Skips the on-wiki runpage check for use in development. Sets `--simulate` unless overridden with `--no-simulate`.
`-h --help` Prints help information
`--version` Prints version information

## Deployment
This bot runs on Toolforge as `inaturalistreviewer` with the `python3.9` Kubernetes container.
The k8s configuration is stored in `deployment.yaml` and `job.yaml` and assumes that there is a python 3.9 virtualenv in `/data/project/inaturalistreviewer/iNaturalistReviewer/venv/`.

To stop the bot:
`kubectl delete deployment inaturalistreviewer.bot`

To start the bot in automatic mode:
`kubectl create -f /data/project/inaturalistreviewer/iNaturalistReviewer/deployment.yaml`

To get the pod status:
`kubectl get pods`

### Updating the bot
With only code changes:
```console
$ git -C /data/project/inaturalistreviewer/iNaturalistReviewer pull
$ kubectl get pods
$ kubectl delete pod <pod id>
```

With code changes and/or dependency updates:
```console
$ webservice shell
$ cd iNaturalistReviewer
$ git pull
$ ./upgrade.sh
$ exit
$ kubectl get pods
$ kubectl delete pod <pod id>
```

```console
$ kubectl delete deployment inaturalistreviewer.bot
$ git -C /data/project/inaturalistreviewer/iNaturalistReviewer pull
$ kubectl create -f /data/project/inaturalistreviewer/iNaturalistReviewer/deployment.yaml
```

TODO: Stick these commands in a bash script

## Commons intergration
The bot is controlled by a [runpage on Commons](https://commons.wikimedia.org/wiki/User:INaturalistReviewBot/Run). If the runpage does not end with True, the bot will stop cleanly. Blocking the bot will also stop it from running. Using the runpage is preferred as it is faster and easier for everyone involved.

The bot looks for images in [Category:iNaturalist review needed](https://commons.wikimedia.org/wiki/Category:INaturalist_review_needed) that transclude {{[iNaturalistreview](https://commons.wikimedia.org/wiki/Template:INaturalistreview)}}.

The bot can only automatically review files with `https://www.inaturalist.org/observations/` links as the source. iNaturalist's API does not currently support retrieving data about `https://www.inaturalist.org/photos/` URLs. The bot will silently skip files with photos links until a decision is made about iNaturalist API support.

If the bot can not automatically determine the license status, it sets `|status=error` with the review date and the reviewer parameters.

If the bot determines that the image is freely licensed on iNaturalist, it sets `|status=pass` with the author, source URL, review date, reviewer, and review license parameters.

If the bot determines that the image is freely licensed on iNaturalist but the Commons license is wrong, it will change the license template on Commons and set `|status=pass-change` with the author, source URL, review date, reviewer, review license, and upload license parameters.

If the bot determines that the image is under a non-free license on iNaturalist, it will add `{{copyvio|Bot license review NOT PASSED: iNaturalist author is using <review_license>` to the top of the file and set `|status=fail` with the author, source url, review date, reviewer, and review license parameters.

### |reason= parameter
The bot will add a `|reason=` parameter when it tags files. This parameter is not read by the template, and exists mostly for debugging.
- `url`: No iNaturalist /photos/ or /observations/ URL was found on the file page.
- `nodata`: No data was recieved from the iNaturalist API. This usually indicates a problem with how the API is called, not the API itself.
- `notmatching`: No photo on iNaturalist was found that matched the Commons file. That usually means the Commons file has been modified or the URL is wrong.
- `sha1`: The Commons file was matched to an iNaturalist photo using a SHA-1 hash. Errors with this reason typically indicate a problem comparing the licenses.
- `ssim`: The Commons file was matched to an iNaturalist photo based on an SSIM score. That score will be included in the reason.

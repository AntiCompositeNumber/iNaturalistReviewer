## Review flow
*This flow is also available as a [flowchart](https://github.com/AntiCompositeNumber/iNaturalistReviewer/blob/master/design_flowchart.svg) in this repository and [as text](https://commons.wikimedia.org/wiki/User:INaturalistReviewBot/Docs) on Commons.*

1. A file in [Category:iNaturalist review needed](https://commons.wikimedia.org/wiki/Category:INaturalist_review_needed) that transcludes [`{{iNaturalistreview}}`](https://commons.wikimedia.org/wiki/Template:INaturalistreview) with no parameters is retrieved.
2. The list of external links from the file page is checked for links to inaturalist.org. The first link to `https://www.inaturalist.org/observations/<id>` or `https://www.inaturalist.org/photos/<id>` that is found is assumed to be the source.
   * Links to other pages on iNaturalist are ignored.
   * The `|source=` parameter of the information template is not specifically checked. This allows more flexibility to deal with different templates and methods of specifying a source.
   * Due to an API limitation, `/photos/<id>` pages are loaded and parsed for an observation URL.
3. An API request is sent to iNaturalist for data about the observation. The API response includes metadata about the observation as well as basic information about the photos contained in that observation.
   * The API is queried based on the observation ID number parsed out of the source URL. If the API returns results for multiple observations, the bot will request human review for the file.
4. Each photo in the observation is downloaded and checked against the [SHA-1 hash](https://www.mediawiki.org/wiki/Manual:Hashing) of the Commons file to determine which photo matches the Commons file.
   * If the file on Commons does match any of the photos on iNaturalist, the bot will request human review for the file. This will happen when the file on Commons has been edited, is not the original size, or has the wrong source URL.
   * If the observation includes duplicate photos, the first photo that matches the hash check will be used. iNaturalist should prevent duplicate photos from being added to an observation.
   * If a `/photos/<id>` link was found on the COmmons page, only that photo will be checked.
   * Fuzzy checking using SSIM was also implemented, but is currently disabled as the pyssim library repeatedly angered the Toolforge k8s OOM killer. It may be re-enabled with a better implementation at a later date.
5. The license of the matched photo is pulled from the API response. The observation API response does not include the version number of Creative Commons licenses. Version 4.0 is assumed because that is the only version currently available on iNaturalist.
6. The observation author is pulled from the API response. Becaues the observation API response does not include author information for specific photos inside an observation, the bot assumes the author of the photo is the same as the author of the observation.
   * This is a safe assumption as other iNaturalist users generally can not add photos to someone else's observation.
7. The license of the Commons file is determined by looking for templates on the file page that are members of [Category:Primary license tags (flat list)](https://commons.wikimedia.org/wiki/Category:Primary_license_tags_(flat_list)).
   * This method will pick up license templates anywhere on the page, including inside `{{self}}`.
8. The Commons and iNaturalist licenses are compared.
   1. If the iNaturalist license is non-free, the file will fail license review.
   2. If the licenses are the same, the file will pass license review.
   3. If the Commons license does not match the free iNaturalist license, the file will pass license review with a changed license.
9. The Commons file page is updated with the results of the review.
   * `{{iNaturalistreview}}` will be filled in wherever it was originally placed.
   * If the license must be changed, the new license will be placed immediately above `{{iNaturalistreview}}`. The old license should be removed from the page, but may not be if it is inside another template. 
   * If license review failed, `{{copyvio}}` will be added to the top of the page and the uploader will be notified.
   * The parameters are used as described in the [template documentation](https://commons.wikimedia.org/wiki/Template:INaturalistreview/doc).

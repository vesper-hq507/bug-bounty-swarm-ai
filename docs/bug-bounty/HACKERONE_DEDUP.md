# HackerOne Historical Duplicate Enrichment

Submission preparation remains local-only. This enrichment improves duplicate review before a researcher manually files a report.

## Historical inputs

For authenticated HackerOne history, the importer retains the normalized subset needed for duplicate analysis:

- report ID, title, state, program and creation time
- structured scope asset
- weakness name / CWE when present
- severity when present
- vulnerability-information text only transiently while deriving a fingerprint

The full historical narrative is not copied into submission manifests.

Public disclosed history is also loaded when a program handle is known. Public records are often sparse; sparse records remain title-fallback candidates and are not promoted to strong structured duplicates.

## Structured fingerprint

A historical record can contribute:

- program
- asset
- endpoint/path
- HTTP method
- CWE
- named parameter
- CVE IDs
- normalized root-cause signature

A historical fingerprint must contain at least two discriminating structured fields before it is used for weighted matching. This prevents a title-only or program-only record from receiving artificially high structured confidence.

## Pagination and bounds

Historical retrieval is paginated and capped at 500 reports per source. The submission CLI currently requests up to 300 owned reports and 300 public reports for the selected program.

Duplicate matches still require researcher review. This feature does not submit anything to HackerOne.

# Human-Approved HackerOne Submission

External HackerOne posting is intentionally separate from draft generation.

The workflow has three explicit stages:

1. **Prepare** a local draft and durable submission manifest.
2. **Approve** the manifest after evidence and duplicate review.
3. **Send** that one approved manifest with an explicit program-handle confirmation.

Draft generation never posts a report.

## 1. Prepare

```bash
pentestswarm submit \
  --platform h1 \
  --program acme \
  --report ./reports/scan.json \
  --state-dir .pentestswarm/state
```

Each finding produces a markdown draft plus a `.submission.json` manifest.

A strict manifest becomes submission-ready only when its referenced durable evidence exists, passes tamper-integrity verification, and has verification status `verified`. Possible duplicates must also be explicitly reviewed.

## 2. Approve

```bash
pentestswarm submit approve ./submissions/example.md.submission.json \
  --by researcher \
  --duplicate-reviewed \
  --state-dir .pentestswarm/state
```

Approval re-opens the durable evidence store and verifies provenance again. This step remains local and performs no network submission.

## 3. Send to HackerOne

```bash
pentestswarm submit send ./submissions/example.md.submission.json \
  --confirm-program acme \
  --state-dir .pentestswarm/state
```

Optional HackerOne identifiers can be supplied when known:

```bash
  --weakness-id 123 \
  --structured-scope-id 456
```

The send command:

- refuses candidate, needs-evidence, duplicate-review, or submission-ready manifests that have not been human-approved;
- requires `--confirm-program` to match the program stored in the approved manifest;
- revalidates durable evidence immediately before the external POST;
- refuses a manifest that already has a submission receipt;
- requires HackerOne API credentials;
- submits only one report with HackerOne's hacker API;
- writes the returned report ID and timestamp back to the manifest.

If send-time evidence verification fails, submission eligibility is revoked and the report is not sent.

## Credentials

The command reads:

- `HACKERONE_API_USER`
- `HACKERONE_API_TOKEN`

The existing configured keychain token can be used as the token fallback. A HackerOne username is still required for Basic Auth.

## External side effect

`submit send` is the only command in this workflow that creates a HackerOne report. It must be invoked explicitly. The deprecated `--live` flag on draft generation does not submit anything.

The local manifest transitions to `submitted` only after HackerOne returns a report ID. The receipt prevents accidental repeat submission from the same manifest.

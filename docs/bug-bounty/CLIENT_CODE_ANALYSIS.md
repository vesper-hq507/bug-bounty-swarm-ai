# Client-Code and Source-Map Analysis

The client-code analyzer is a static, bounded analysis layer. It does not execute JavaScript.

## What it extracts

From a local JavaScript artifact and optional source map it records only stable security-relevant signals:

- application/API routes
- WebSocket and EventSource endpoints
- named query/search parameters
- feature-flag names
- role-gating hints
- workflow state/transition names
- source-map source filenames

These are hypotheses and targeting hints, not vulnerabilities.

## Safety bounds

- JavaScript input: maximum 4 MiB
- source-map input: maximum 8 MiB
- source files inspected from one map: maximum 128
- emitted signals: maximum 512
- no JavaScript evaluation
- no automatic source-map download
- no automatic requests to routes extracted from source
- browser recon records same-origin script URLs only; script bodies remain separate artifacts

## CLI

Analyze a local asset:

    pentestswarm client-code analyze app.js --url https://example.test/assets/app.js

Include a local source map:

    pentestswarm client-code analyze app.js       --url https://example.test/assets/app.js       --source-map app.js.map

Enrich an existing monitor snapshot:

    pentestswarm client-code analyze app.js       --url https://example.test/assets/app.js       --source-map app.js.map       --snapshot current-snapshot.json

The enriched snapshot can then be compared with `pentestswarm monitor diff`. Only newly observed client-code signals become targeted re-test suggestions. Hunter Guidance applies program path restrictions before surfacing those suggestions.

## Browser integration

When browser recon is enabled, the attack surface now retains same-origin JavaScript asset URLs observed during the rendered page load. Those URLs seed the JavaScript inventory in monitor snapshots. Static content analysis remains a separate, explicit local-artifact step.

# Mobile Workflow Foundation

Mobile support starts with **offline traffic analysis**, not autonomous device exploitation.

The goal is to let Android/iOS observations enter the same scope, identity, workflow, evidence, and Hunter Guidance systems used by web/API campaigns.

## Supported inputs

Current v1 accepts a HAR export from a controlled mobile session.

Typical sources include a researcher-controlled interception proxy or browser/devtool-compatible capture export. The agent does not start a proxy, bypass certificate pinning, root/jailbreak a device, or inject traffic.

Limits:

- HAR file: 32 MiB maximum
- transactions: first 1,000
- request/response body retained in memory for analysis: 256 KiB per side
- Authorization, Cookie, Set-Cookie, API-key and proxy-auth headers are redacted during import
- evidence records remain `unverified` until separately verified

## Analyze one identity

```bash
pentestswarm mobile analyze user-a.har \
  --platform android \
  --app-id com.example.app \
  --identity user-a \
  --role user \
  --session-ref vault:user-a \
  --scope scope.yaml \
  --policy program-config.yaml \
  --rules workflow-rules.json
```

The command:

1. parses and bounds the HAR locally,
2. strips sensitive authentication headers,
3. validates every observed URL against the supplied program scope,
4. skips out-of-scope or program-disallowed paths,
5. writes sanitized, tamper-evident provenance records,
6. derives workflow events,
7. analyzes supplied workflow invariants,
8. produces Hunter Guidance for concrete workflow hypotheses,
9. creates a monitor-compatible endpoint snapshot.

No request is replayed.

## Compare controlled identities

```bash
pentestswarm mobile diff owner.har actor.har \
  --platform ios \
  --app-id com.example.app \
  --owner-identity user-a \
  --actor-identity user-b \
  --scope scope.yaml \
  --policy program-config.yaml
```

The differential command compares matching in-scope object requests already present in both captures. It uses the existing multi-identity authorization engine to distinguish:

- equivalent access,
- different responses,
- owner-only enforcement,
- possible unexpected non-owner access.

It does not send a second request to the target.

## Identity and secrets

`--identity`, `--owner-identity`, and `--actor-identity` are researcher-controlled aliases.

`--session-ref` is an opaque reference only. Do not place access tokens, passwords, cookies, or raw session material in that flag. Imported HAR authentication headers are redacted before normalized capture data is retained.

## Scope and policy behavior

Mobile observations do not get a special scope exemption. Any URL outside `scope.yaml`, or beneath a disallowed policy path, is excluded from workflow/evidence analysis and surfaced as skipped.

The policy-version marker written to imported evidence is derived from the supplied scope/policy files and explicitly identifies this as an offline mobile import. It is not represented as a live network authorization decision.

## Future device adapters

ADB, simulator/emulator control, device instrumentation, certificate-pinning workflows, and native binary analysis are intentionally outside this foundation. Any future adapter must enter through the same universal policy gateway, approval broker, identity model, and evidence pipeline rather than becoming a bypass path.

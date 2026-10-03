# Campaign Preflight

`campaign preflight` is the post-development gate for a real authorized bug-bounty campaign.

It performs **no target network traffic**. Its job is to prove that the campaign configuration is safe enough to start.

## Command

```bash
pentestswarm campaign preflight https://target.example \
  --scope scope.yaml \
  --policy program-config.yaml \
  --max-duration 30m
```

If the program policy did not publish a request limit, supply an explicit global limit. When both are present, preflight uses the stricter value:

```bash
  --max-rps 1
```

For authenticated testing, add controlled identities by reference:

```bash
  --identity user-a:user:vault:user-a \
  --identity user-b:user:vault:user-b \
  --primary-identity user-a
```

Sensitive capabilities are explicit and repeatable:

```bash
  --approve-capability state-change
```

Valid capability names are enforced by the approval broker.

## Checks

A READY result requires all of the following:

- target is inside the supplied scope;
- a positive global request limit is active, either from the program policy or `--max-rps`;
- a hard campaign duration is configured;
- the requested mode is compatible with extracted program restrictions;
- controlled identity/session references are structurally valid;
- any pre-approved sensitive capabilities are recognized;
- the durable state directory is writable;
- the durable cleanup ledger can initialize;
- the universal policy gateway accepts the target and produces a versioned decision without sending network traffic;
- the strict controlled benchmark suite passes.

If the policy forbids automated scanning, preflight additionally requires:

- no active-scan mode;
- `--safe-mode`;
- `--assist`.

Program restrictions such as no DoS, no brute force, no social engineering, and no physical testing are surfaced as review warnings.

## Policy files

Generate the constraints file from the program rules first:

```bash
pentestswarm program inspect h1:<program-handle> --yaml > program-config.yaml
```

Scope and policy are separate inputs on purpose. Scope answers **where** the campaign may operate; program constraints answer **how** it may operate.

## Exit behavior

- READY: exit code 0
- NOT READY: exit code 1
- command/configuration error: exit code 2

JSON output is available through the global `--json` / `--output json` option.

## First authorized pilot

The recommended first real-program sequence is:

1. import and manually review program scope;
2. fetch/read the current program rules;
3. create controlled identities and session references;
4. run `campaign preflight`;
5. resolve every failed required check;
6. start with read-only observation / Hunter Guidance;
7. grant state-changing, upload, concurrency, account-change, or proof-impact capabilities only when the program permits the exact action;
8. preserve evidence and recovery state;
9. prepare a report locally;
10. review duplicates and evidence;
11. explicitly approve the report;
12. use `submit send` only when you deliberately want to create the HackerOne report.

The preflight command is not authorization. The researcher remains responsible for using the current program scope and rules.

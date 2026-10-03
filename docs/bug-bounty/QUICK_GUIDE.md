# Bug Bounty Swarm AI — Quick Guide

This guide is the operator-facing path for using the fork at
`vesper-hq507/bug-bounty-swarm-ai`.

The core rule is simple: **choose an authorized program, import its current
scope and rules, pass the zero-traffic preflight, and only then allow target
traffic.** Report submission remains human-approved.

## 1. Build or update the agent

Fresh clone:

```bash
git clone https://github.com/vesper-hq507/bug-bounty-swarm-ai.git
cd bug-bounty-swarm-ai
make build
./bin/pentestswarm --version
```

Update an existing clone:

```bash
cd ~/bug-bounty-swarm-ai
git fetch origin
git switch main
git pull --ff-only origin main
make build
```

If you are working from a release ZIP instead, extract the new ZIP into a new
directory, preserve your local secrets/configuration outside the source tree,
then run `make build` in the new directory. Do not copy old binaries over a
new source checkout.

Recommended health checks:

```bash
./bin/pentestswarm doctor
./bin/pentestswarm --help
```

## 2. What the agent does today

The fork can:

1. enforce a fail-closed policy gateway before target actions;
2. import bug-bounty scope and inspect HackerOne program rules;
3. maintain multiple controlled identities by session reference;
4. guide BOLA/IDOR/BFLA and other authorization-differential testing;
5. preserve evidence provenance and recovery/cleanup state;
6. analyze workflow and business-logic traces;
7. monitor target-surface changes and generate bounded re-test suggestions;
8. analyze JavaScript/client code and realtime WebSocket/SSE observations;
9. run controlled benchmark and mobile-workflow planning features;
10. prepare HackerOne submission drafts, run historical duplicate checks, and
    require explicit approval before an external submission;
11. run the zero-target-traffic campaign preflight gate; and
12. discover/filter public HackerOne opportunities before you choose a pilot.

None of these features makes a program or asset authorized automatically.
The current program rules and scope remain the source of authorization.

## 3. Discover HackerOne opportunities

The discovery module reads HackerOne's public **Campaigns & top-paying
opportunities** section. It does **not** contact program targets.

Default view:

```bash
./bin/pentestswarm opportunity discover
```

Sort by highest possible bounty:

```bash
./bin/pentestswarm opportunity discover \
  --sort max-bounty \
  --order desc
```

Sort by lowest number of awarded reporters:

```bash
./bin/pentestswarm opportunity discover \
  --sort hackers-paid \
  --order asc
```

> `hackers-paid` is a CLI convenience name for HackerOne's public
> **Number of awarded reporters** metric.

Example shortlist: no more than 100 awarded reporters, at least 90% response
efficiency, and a possible bounty of at least $10,000:

```bash
./bin/pentestswarm opportunity discover \
  --max-awarded-reporters 100 \
  --min-response-efficiency 90 \
  --min-ceiling-bounty 10000 \
  --sort hackers-paid \
  --order asc
```

Enrich each card with the public program-detail statistics and sort by total
bounties paid:

```bash
./bin/pentestswarm opportunity discover \
  --enrich \
  --sort total-paid \
  --order desc
```

Machine-readable output:

```bash
./bin/pentestswarm opportunity discover \
  --enrich \
  --json > opportunities.json
```

Useful filters:

```text
--min-floor-bounty USD
--min-ceiling-bounty USD
--max-awarded-reporters N
--max-hackers-paid N
--min-response-efficiency PERCENT
--min-total-paid USD
--limit N
```

Supported sort fields:

```text
name
min-bounty
max-bounty
awarded-reports
hackers-paid
response-efficiency
total-paid
```

`total-paid` automatically enables enrichment because that value lives on the
public program detail page rather than the opportunity card.

The module requires a Chromium-family browser. If auto-detection does not find
one, point the agent to the approved browser runtime:

```bash
export PENTESTSWARM_BROWSER=/path/to/chrome-or-chrome-headless-shell
```

## 4. Choose the program yourself

Opportunity Discovery is a factual filter, not an authorization or automatic
target selector.

After reviewing the output, choose the HackerOne handle you want to investigate,
for example:

```text
h1:<program-handle>
```

Do not provide the agent with passwords, cookies, API tokens, or raw session
secrets in chat.

## 5. Inspect the current HackerOne rules

Print the extracted constraints:

```bash
./bin/pentestswarm program inspect h1:<program-handle>
```

Save the machine-readable constraints used by preflight:

```bash
./bin/pentestswarm program inspect h1:<program-handle> --yaml \
  > program-config.yaml
```

Read the original current HackerOne program policy as well. Automated parsing
helps enforce known restrictions, but it does not replace human review.

## 6. Import and review current scope

```bash
./bin/pentestswarm scope import h1 <program-handle> \
  --out scope.yaml
```

Open `scope.yaml` and manually verify the assets before any live run.

If you later re-import scope, compare versions:

```bash
./bin/pentestswarm scope diff previous-scope.yaml scope.yaml
```

## 7. Configure controlled identities only when needed

Authenticated identities are referenced rather than copying secrets into
blackboard text:

```text
--identity user-a:user:vault:user-a
--identity user-b:user:vault:user-b
--primary-identity user-a
```

Use only accounts you own/control and only where the program permits the
intended workflow.

## 8. Run the zero-target-traffic preflight

Minimal example:

```bash
./bin/pentestswarm campaign preflight https://authorized.example \
  --scope scope.yaml \
  --policy program-config.yaml \
  --max-duration 30m \
  --max-rps 1
```

Authenticated example:

```bash
./bin/pentestswarm campaign preflight https://authorized.example \
  --scope scope.yaml \
  --policy program-config.yaml \
  --identity user-a:user:vault:user-a \
  --identity user-b:user:vault:user-b \
  --primary-identity user-a \
  --max-duration 30m \
  --max-rps 1
```

Preflight checks scope, policy constraints, identities, approval capabilities,
durable state/cleanup storage, the policy gateway, and the controlled benchmark
suite. It sends **no target traffic**.

Do not start a campaign until required checks report `READY`.

## 9. Use Hunter Guidance before active testing

Given an existing attack-surface snapshot:

```bash
./bin/pentestswarm guide attack-surface.json \
  --policy program-config.yaml \
  --limit 5
```

With controlled identities:

```bash
./bin/pentestswarm guide attack-surface.json \
  --policy program-config.yaml \
  --identity user-a:user:vault:user-a \
  --identity user-b:user:vault:user-b
```

Hunter Guidance does not execute target traffic. It explains:

- the hypothesis;
- the recommended tool/test;
- expected signal;
- required identity;
- approval class;
- why the test is useful; and
- the stopping condition.

## 10. Start live work only inside approved scope

For a live campaign, use the current scope file and the most conservative mode
compatible with the program's rules.

The general scan form is:

```bash
./bin/pentestswarm scan <authorized-target> \
  --scope scope.yaml \
  --swarm
```

Do not treat this generic command as permission to scan. The preflight result,
current rules, and exact asset authorization determine whether a particular
live action is permitted.

## 11. Analyze workflows and target changes

Business-logic trace analysis without target traffic:

```bash
./bin/pentestswarm workflow analyze trace.json
```

Build a workflow replay plan without executing it:

```bash
./bin/pentestswarm workflow replay-plan trace.json \
  --from <state-a> \
  --to <state-b>
```

Create/diff target snapshots:

```bash
./bin/pentestswarm monitor snapshot attack-surface.json --out baseline.json
./bin/pentestswarm monitor diff baseline.json current.json
```

The monitor recommends bounded re-tests instead of automatically rescanning the
whole program.

## 12. Prepare and review a HackerOne report

Create local HackerOne-formatted drafts:

```bash
./bin/pentestswarm submit \
  --platform h1 \
  --program <program-handle> \
  --report ./reports/scan.json
```

Review the generated Markdown and submission manifest. The assistant can also
compare against available historical HackerOne data for duplicate signals.

Optional draft quality check:

```bash
./bin/pentestswarm report polish ./submissions/<draft>.md
```

## 13. Explicitly approve before external submission

Approval is a separate action:

```bash
./bin/pentestswarm submit approve \
  ./submissions/<draft>.md.submission.json
```

Only when you deliberately want to create the HackerOne report:

```bash
./bin/pentestswarm submit send \
  ./submissions/<draft>.md.submission.json \
  --confirm-program <program-handle>
```

The send path revalidates the approved manifest/evidence and requires the
program handle confirmation.

## 14. Recommended first-pilot sequence

Use this order for the first authorized real-program pilot:

1. `opportunity discover` to build a factual shortlist;
2. manually choose one program;
3. inspect its current rules;
4. import and manually review its current scope;
5. configure controlled identities only if needed;
6. run `campaign preflight`;
7. resolve every required failure;
8. begin with read-only observation and Hunter Guidance;
9. grant mutating capabilities only when the exact action is permitted;
10. preserve evidence/recovery state throughout the campaign;
11. verify a candidate finding before drafting a report;
12. run historical duplicate checks;
13. review the report yourself;
14. explicitly approve the manifest; and
15. invoke `submit send` only when you intend to submit.

## 15. Key commands at a glance

```bash
pentestswarm doctor
pentestswarm opportunity discover
pentestswarm program inspect h1:<handle>
pentestswarm scope import h1 <handle> --out scope.yaml
pentestswarm campaign preflight <target> --scope scope.yaml --policy program-config.yaml
pentestswarm guide attack-surface.json --policy program-config.yaml
pentestswarm workflow analyze trace.json
pentestswarm monitor diff before.json after.json
pentestswarm submit --platform h1 --program <handle> --report <report.json>
pentestswarm submit approve <submission-manifest.json>
pentestswarm submit send <submission-manifest.json> --confirm-program <handle>
```

## 16. Next step after this feature

Once the Opportunity Discovery module passes CI, use it to generate the first
shortlist. The operator then selects the pilot program; the agent does not make
that authorization decision automatically.

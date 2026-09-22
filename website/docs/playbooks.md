---
sidebar_position: 8
title: Playbooks
---

# Playbooks

**Playbooks are deterministic attack chains the swarm can execute.** Where the
stigmergic scheduler lets the swarm improvise — reacting to findings as they
land — a playbook gives it a known-good, repeatable sequence for a specific job:
a bug-bounty sweep, external attack-surface mapping, a CI/CD security gate, an
internal-network pass, or a CTF solve.

Think of them as the difference between "explore this target" and "run this
proven procedure against this target." Playbooks make runs reproducible and
easy to drop into automation.

:::note Playbook vs. swarm mode
A **playbook** runs a fixed, known-good sequence — repeatable and predictable. A
**[scan mode](./modes.md)** (via `--mode`) instead steers the *improvising*
swarm toward an objective. Reach for a playbook when you want the same procedure
every time; reach for a swarm scan when you want the swarm to react to what it
finds.
:::

## How a playbook runs

A playbook is a list of **phases**, each declaring the **tools** to run (with
their options) and a **`post_analysis`** instruction. The engine executes it
deterministically:

1. **Runs each phase's tools in order**, passing every tool its declared options
   (e.g. `nuclei` with specific `templates`/`tags`, `httpx` with extra `paths`).
   Every tool call is **scope-enforced** at the tool layer.
2. **Turns tool output into findings** using the same extractor the swarm uses,
   so playbook findings are identical in shape to swarm findings.
3. **Runs the phase's `post_analysis`** through the LLM (GLM-5.3-Flash on
   Together) as a reasoning step over that phase's output, streamed live.
4. **Writes a report** — an LLM-synthesised report when a provider is configured,
   otherwise a deterministic findings summary, so a run always leaves an artifact.

`${variable}` references in a tool's options are substituted from the playbook's
resolved variables before the tool runs.

## Running a playbook

```bash
pentestswarm playbook run <name> --target <target>
```

For example:

```bash
pentestswarm playbook run bug-bounty --target example.com
```

Flags:

| Flag | Purpose |
|------|---------|
| `--target <t>` | The target (URL / domain / IP). Binds to whatever the playbook names its target variable. **Required.** |
| `--scope <list>` | Extra authorized scope beyond the target — CIDRs/domains, comma-separated. |
| `--format <fmt>` | Report format: `md` (default) · `json` · `html` · `all`, or a comma-separated list. |
| `--report-dir <dir>` | Where to write the report (default `./reports`). |

The bundled playbooks are **embedded in the binary**, so `playbook run <name>`
and `playbook list` work on any install (npm, Homebrew, `go install`, Docker) —
no repo checkout needed. A same-named file in `./playbooks` overrides the
embedded copy, so you can fork a bundled playbook by dropping an edited YAML
there.

## Bundled playbooks

The repo ships a set of playbooks under
[`playbooks/`](https://github.com/Armur-Ai/Pentest-Swarm-AI/tree/main/playbooks):

- `bug-bounty` — a bug-bounty-style sweep
- `external-asm` — external attack-surface mapping
- `ci-cd-security` — a security gate for CI/CD pipelines
- `internal-network` — an internal-network pass
- `ctf-solver` — CTF solving
- `api-security` — API-focused attacks
- `owasp-top10` — OWASP Top 10 coverage
- `cve-2026-75650-magento-stylesmuggler` — hunts CVE-2026-75650, the
  unauthenticated Adobe Commerce / Magento template-engine RCE (see below)
- `cloud-exploitation` — AWS-first cloud assessment that goes past misconfig
  scanning into **IAM privilege-escalation pathing** (cloudsplaining → pacu),
  pairing with the swarm's SSRF → cloud-metadata credential-theft chain
- `graphql-audit` — locate the GraphQL endpoint, dump the schema via
  introspection, then probe field-level authz, IDOR on node ids, injection, and
  alias/batching amplification

Each is a YAML file — open one to see the exact chain it runs.

### Rapid-response CVE playbook: StyleSmuggler (CVE-2026-75650) {#cve-2026-75650}

When a high-profile CVE drops, a playbook lets the swarm hunt it autonomously —
fingerprint, verify, report — instead of you checking hosts by hand.

`cve-2026-75650-magento-stylesmuggler` targets **StyleSmuggler**: the
unauthenticated template-engine RCE in **Adobe Commerce / Magento** (CVSS 10.0,
CWE-1336, on CISA KEV, exploited in the wild since 2026-09-04, affecting
2.4.4–2.4.9). The swarm:

1. **Fingerprints** Magento / Adobe Commerce and recovers the version.
2. **Assesses exposure** — is the build in the vulnerable range and un-hotfixed
   (pre-VULN-39341)?
3. **Corroborates** with the nuclei CVE template when available.
4. **Safely verifies** — a *benign, non-destructive* canary proves the
   vulnerable template path is reachable **without running any attacker code**.
5. **Reports** with evidence, CVSS, and remediation (apply VULN-39341, rotate
   the encryption key + credentials, triage for backdoors).

```bash
pentestswarm playbook run cve-2026-75650-magento-stylesmuggler \
  --target https://shop.example.com
```

The playbook run is scope-bound to `--target`. For a full active scan with an
explicit scope, budget cap, and safe-mode, the equivalent `scan` form is:

```bash
pentestswarm scan https://shop.example.com \
  --scope shop.example.com --swarm --safe-mode --budget 5
```

:::danger Detection & verification only — authorized targets
This playbook is deliberately **non-weaponized**: it confirms exposure and
reachability, it does not execute code or persist anything, and it ships no
working exploit payload. Run it only against stores you own or are explicitly
contracted to test. See [Security & Responsible Use](./security.md).
:::

:::note Authoring is evolving
The playbook format and authoring workflow are still evolving. The bundled
playbooks are the best current reference for structure; dedicated authoring
docs are on the way. Ask in [Discord](https://discord.gg/6qtkhpW8tk) if you're
writing your own and want a hand.
:::

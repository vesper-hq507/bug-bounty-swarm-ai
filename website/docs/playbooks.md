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
- `cloud-exploitation` — AWS-first cloud assessment that goes past misconfig
  scanning into **IAM privilege-escalation pathing** (cloudsplaining → pacu),
  pairing with the swarm's SSRF → cloud-metadata credential-theft chain
- `graphql-audit` — locate the GraphQL endpoint, dump the schema via
  introspection, then probe field-level authz, IDOR on node ids, injection, and
  alias/batching amplification

Each is a YAML file — open one to see the exact chain it runs.

:::tip Hunting specific CVEs? Use exploit chains
CVE-specific attacks (like the Magento **StyleSmuggler** RCE) now live as
**[exploit chains](./exploit-chains.md)**, a first-class concept separate from
playbooks — e.g. `pentestswarm chain run magento-stylesmuggler-rce --target …`.
Playbooks are *workflows* (which tools, in what order); exploit chains are
*named, CVE-tied attacks* (fingerprint → verify each link → report).
:::

:::note Authoring is evolving
The playbook format and authoring workflow are still evolving. The bundled
playbooks are the best current reference for structure; dedicated authoring
docs are on the way. Ask in [Discord](https://discord.gg/6qtkhpW8tk) if you're
writing your own and want a hand.
:::

# Roadmap

Where Pentest Swarm AI is headed. This is the public, high-level view — the
major capabilities we're building and the order we expect to ship them. Dates
are intentionally omitted; we ship when it's real and tested. Follow the
[GitHub Project board](https://github.com/orgs/Armur-Ai/projects/1) for live
status, and join the [Discord](https://discord.gg/6qtkhpW8tk) to shape it.

> Legend — **shipped**: in `main`, tested · **in progress**: actively being
> built · **next**: committed, not started · **planned**: on the map.

---

## 1. The Adaptive Swarm — runtime reaction to discoveries  ·  *shipped · expanding*

The swarm reacts to what it finds *as it finds it*. An identifier, token, or
object reference surfaced by one agent becomes shared state the whole swarm can
act on — turning a single leaked detail into cross-user and cross-endpoint
attacks that nobody scripted. This is the headline capability that separates a
swarm from a checklist: emergent attack chains, composed at runtime.

Now live: **adaptive attack-path scoring** — the swarm generates several
candidate strategies for a finding, scores them against live state, pursues the
best-scored one first, and reinforces what actually works through the pheromone
signal (so exploration and exploitation stay balanced, not stuck on an early
guess). We keep deepening how strategies are generated and scored.

## 2. Self-Correcting Attacks — closed-loop replanning  ·  *shipped · deepening*

Attacks that heal themselves. When a step fails — the wrong content type, a
missing token, an unexpected response — the swarm reads the failure and adjusts:
it re-scores the remaining candidate strategies with the fresh outcome and
pursues the next-best, falling back to a model-adjusted retry. The closed loop
is live; we're extending how far ahead it plans and branches.

## 3. On-Demand Specialist Agents — dynamic sub-agents  ·  *planned*

The swarm spins up purpose-built agents at runtime — a session-holder to keep
an authenticated context, a fuzzer for a newly discovered parameter, a
chain-builder for a specific API — and retires them when the work is done.
Specialization without a fixed roster.

## 4. Attack Playbook Library — verified, expanding coverage  ·  *in progress*

A growing library of verified, reproducible attack chains across the OWASP API
& Web Top 10 — broken object-level authorization (BOLA/IDOR), broken
authentication, mass assignment, injection (SQL/NoSQL/command), SSRF, excessive
data exposure, and more. Each is confirmed against a live target and executed
end-to-end with evidence. Live today: **BOLA/IDOR, JWT/token forgery, mass
assignment, BFLA (function-level privilege escalation), SSRF → cloud-metadata
credential theft, GraphQL abuse, auth-bypass, business-logic race conditions,
SQL injection with proof-of-impact, and NoSQL injection**, plus a
**rapid-response CVE track** (a fresh critical CVE becomes a hunt-and-verify
playbook) and a **cloud exploitation / IAM privesc** playbook. Next: broadening
coverage and going deeper on each class.

Also live: **exploit chains** — a growing library of named, CVE-tied attack
chains (SSRF→RCE, auth-bypass→command-injection, SQLi→webshell) behind real
breaches, that the swarm fingerprints, *safely verifies*, and reports. The binary
ships a lean curated default set; the rest arrive **on demand** (`chain update`),
so a fresh chain can land the day a CVE drops — without a binary upgrade. New
chains are a great community contribution.

Backing this: a growing set of **bundled practice targets** you can attack with
one command (`--lab`, or pick one in `pentestswarm run`) — crAPI and Juice Shop
today, with VAmPI, DVGA, WebGoat and more on deck. We run the swarm against each
to find where it falls short and harden it, and you get safe, legal targets to
try it on yourself.

## 5. Live Mission Control — real-time visibility  ·  *next*

Watch the swarm work: agents activating, the pheromone graph shifting, findings
streaming in, attack chains drawn as they form — plus polished, shareable
reports. Understand *why* the swarm did what it did, not just what it found.

## 6. Benchmark-Proven — transparent, public scores  ·  *planned*

Published results on the recognised agentic-security benchmarks (Cybench,
AutoPenBench, CVE-Bench, and the XBOW validation set) with a fully transparent
methodology — the mode, the budget, the failures. Credibility through numbers,
not adjectives.

## 7. Tool & Platform Ecosystem — plug into your stack  ·  *in progress*

Deeper reach through the tools teams already use — Burp Suite, ZAP, Metasploit,
sqlmap and more via a clean adapter and MCP layer — plus first-class CI/CD
integration and a GitHub Action, so the swarm runs where your security work
already lives. The adapter interface is deliberately small, and **new tool
adapters are a great first contribution** — the toolbox already spans recon,
content discovery, WAF fingerprinting, injection, and cloud, several of them
community-contributed.

## 8. Continuous Attack-Surface Monitoring — always-on  ·  *planned*

Point the swarm at a scope once and let it watch: scheduled re-scans, diffing
run-over-run, and alerts when the attack surface changes or a new exposure
appears. From one-shot engagement to continuous coverage.

## 9. Cross-Engagement Kill-Chains — attack paths across the whole target  ·  *planned*

Today the swarm chains steps *within* an attack. Next it composes findings from
*different* agents into a single narrative kill-chain — an information leak
feeding a credential, feeding an authorization bypass, feeding account takeover —
scored end-to-end and mapped to MITRE ATT&CK. The whole engagement as one graph,
not a list of isolated findings.

---

*Provider-agnostic and local-first throughout: run against frontier models or
fully local/air-gapped, your data never leaving your environment. A fine-tuned,
purpose-built Pentest Swarm model rides on top of this work.*

Have an opinion on the order, or a capability you need sooner? Open an issue or
say hi in [Discord](https://discord.gg/6qtkhpW8tk).

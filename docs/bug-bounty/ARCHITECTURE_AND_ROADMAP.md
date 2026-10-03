# Bug Bounty Swarm AI — Integration Architecture & Roadmap

> Status: Phase 0–7 foundations merged; runtime integration hardening remains
>
> Fork baseline: `Armur-Ai/Pentest-Swarm-AI` main at `f9993275d7e1b91c7978e87144ae4c63f1d347c8`
>
> Working branch: `integration/bug-bounty-platform-foundation`
>
> Goal: evolve Pentest Swarm AI into a policy-aware, evidence-first bug-bounty hunting platform for authorized programs, with HackerOne as the first deeply integrated platform.

## Implementation checkpoint — 2026-10-02

Merged and CI-validated on `main`:

- **Phase 0 + Phase 1:** campaign reliability, fail-closed live scope handling, universal policy gateway, central target traffic controls, policy-aware HTTP/browser/tool/exploit/plugin paths.
- **Phase 2:** multi-identity registry, session references, ownership map, policy-aware per-identity HTTP clients, bounded read-only BOLA/IDOR differential testing.
- **Phase 3 foundation:** tamper-evident evidence records, secret redaction, provenance references and integrity-protected recovery checkpoints.
- **Phase 4:** non-executing hunter guidance CLI that ranks bounded next tests with policy compatibility, identity requirement, expected signal and stop condition.
- **Phase 5:** workflow state graph, invariant analysis, sequence/role/ownership/terminal-state hypotheses, replay planning and gated race-test candidates.
- **Phase 6:** target snapshots/diffs with targeted change-only re-test plans instead of whole-scope rescans.
- **Phase 7:** structured duplicate fingerprints, provenance-aware HackerOne submission manifests, redacted reproducible drafts and explicit local human approval. External live submission remains disabled.

Current integration hardening before the platform should be called unattended bug-bounty ready:

- wire evidence-record creation into every runtime observation/verification path, not only the evidence model and reporting references
- persist evidence and recovery checkpoints beyond in-memory stores
- expose multi-identity/session-reference configuration through campaign/CLI/browser flows
- derive workflow events automatically from browser/API traces
- feed target-monitor diffs directly into the hunter-guidance queue
- populate structured duplicate fingerprints for historical HackerOne submissions when the platform data supports it
- complete the capability-based approval broker for stateful/race actions
- keep external HackerOne submission human-approved and disabled by default until the submission transport receives its own policy/approval review

The merged Phase 7 `main` checkpoint is `d2b30fb145571d77757133bdd5737488a7eb9510`; CI passed build, lint, tests, shell checks and Docker validation.

## 1. Product boundary

Pentest Swarm AI remains the execution and adaptive-reasoning engine. Bug Bounty Swarm AI adds the control plane that decides **whether**, **where**, **how fast**, **under which identity**, and **with what approval/evidence requirements** testing may occur.

The control plane is authoritative. No agent, tool adapter, browser action, MCP action, built-in HTTP primitive, or future plugin may bypass it.

```text
Bug Bounty Swarm AI
│
├── Program Policy / Scope Brain
├── Hunter Guidance Engine
├── Approval & Safety Broker
├── Evidence / Audit / Recovery
│
├── Pentest Swarm Engine
│   ├── Stigmergic blackboard
│   ├── Adaptive attack planning
│   ├── Recon/classify/exploit/report agents
│   ├── Tool adapters
│   ├── Browser API discovery
│   ├── Failure classification
│   └── Verified PoCs
│
├── Multi-Identity Engine
├── Universal Policy Gateway
├── Workflow / Business-Logic Engine
├── Target-Change Monitor
└── HackerOne Reporting Assistant
```

## 2. Non-negotiable safety invariants

These rules define the architecture and must be enforced in code, not only in prompts.

1. **Every outbound target action passes one policy decision point.**
   - Go HTTP requests
   - browser navigation and browser-initiated target requests
   - built-in `httpreq`
   - external tools
   - exploit chains
   - MCP/plugin actions that can reach a target

2. **Scope is fail-closed.**
   - Empty or unreadable scope cannot broaden access.
   - Scope removal during a campaign stops future actions against the removed asset.
   - Redirects and derived hosts are revalidated.

3. **Program rules are executable constraints.**
   - required headers
   - maximum request rate
   - prohibited techniques
   - excluded paths/assets
   - automation restrictions
   - program-specific notes that require human acknowledgement

4. **Approval is capability-based, not cosmetic.**
   - Passive/recon actions can have one approval class.
   - Stateful tests, account changes, uploads, race tests, and proof-of-impact actions require stricter classes.
   - Destructive actions remain blocked unless explicitly supported by policy and approved by the operator.

5. **Evidence precedes reporting.**
   - A finding is not "verified" solely because an LLM says it is.
   - Verification must link to reproducible evidence and the exact identity/policy context used.

6. **Secrets are minimized and redacted.**
   - Session tokens, API keys, cookies and credentials must not be copied into model prompts, logs, reports or long-term evidence unless explicitly required and protected.

7. **Recovery is deterministic.**
   - Mutating test steps register cleanup before execution.
   - Interrupted campaigns preserve enough state to resume analysis without replaying unsafe actions.

8. **Human approval remains mandatory before external submission.**
   - The reporting assistant may draft, deduplicate and package evidence.
   - It must not autonomously submit HackerOne reports by default.

## 3. Existing upstream components to preserve

The fork already contains several strong primitives. Extend these rather than replacing them.

### Scope and policy

Existing:
- `internal/scope/validator.go` — domain/CIDR validation and command target checks
- `internal/scope/audit.go` — structured allow/violation logging
- `internal/scope/differ.go` — scope diffing
- `internal/scope/watcher.go` — dynamic scope-file reload
- `internal/scope/importer/hackerone` — HackerOne structured-scope import
- `internal/scope/programterms` — rule-of-engagement text parsing

Direction:
- Promote these from "scope helpers" into the input side of a universal policy gateway.
- Treat HackerOne policy parsing as advisory until each parsed constraint is enforced end-to-end.

### Authenticated sessions

Existing:
- `internal/session/session.go` — one authenticated header/cookie/bearer context with browser-like defaults

Direction:
- Keep `Session` as the low-level request decorator.
- Add a multi-identity abstraction above it; do not overload one session object to represent all actors.

### Execution safety

Existing:
- `internal/agent/exploit/executor.go`
  - scope checks
  - executable allowlist
  - safe mode
  - human confirmation hook
  - command timeout
  - cleanup registration
  - stateful variable capture across chains

Direction:
- Route its final authorization decision through the universal policy gateway.
- Preserve its allowlist and cleanup logic as defense-in-depth.

### Browser discovery

Existing:
- `internal/browser/browser.go`
  - real Chromium-family browser
  - authenticated headers
  - rendered DOM
  - same-origin XHR/fetch discovery

Direction:
- Add policy-aware browser routing/interception.
- Add workflow actions, identity contexts, screenshots and trace evidence.
- Revalidate redirects and browser-discovered hosts through policy.

### Pipeline / lifecycle

Existing:
- `internal/pipeline/cleanup_*.go`
- `internal/pipeline/statemachine.go`
- `internal/pipeline/context.go`

Direction:
- Reuse for campaign checkpoints, cleanup obligations and resumable workflow state.

### HackerOne / reporting

Existing:
- `internal/bugbounty/hackerone.go`
- `internal/bugbounty/scope_importer.go`
- `internal/bugbounty/dedup.go`
- `internal/bugbounty/formatter.go`

Direction:
- Consolidate overlapping HackerOne clients.
- Upgrade duplicate detection beyond title/word overlap.
- Separate "report candidate" from "submission-ready report."
- Keep submission human-approved.

## 4. New module boundaries

### 4.1 Universal Policy Gateway — P0

Proposed package:
`internal/policygateway`

Primary responsibility: make a deterministic allow/deny/approval decision for every target-directed action.

Suggested model:

```go
type Action struct {
    CampaignID   string
    ActorID      string
    Kind         ActionKind
    Method       string
    URL          string
    Tool         string
    Technique    string
    Path         string
    MutatesState bool
    Metadata     map[string]string
}

type Decision struct {
    Allowed          bool
    RequiresApproval bool
    Reason           string
    RequiredHeaders  map[string]string
    RateClass        string
    PolicyVersion    string
}
```

Gateway inputs:
- normalized scope
- parsed program terms
- operator overrides/acknowledgements
- live program/scope version
- rate state
- action classification
- actor identity

Enforcement points:
- HTTP transport wrapper
- browser network interception/navigation
- exploit executor
- tool coordinator
- MCP/plugin bridge

The gateway must be the **single authoritative policy decision API** even though lower layers continue their own scope/safe-mode checks.

### 4.2 Hunter Guidance Engine — P0/P1

Proposed package:
`internal/guidance`

Purpose: act as the researcher's guide, not merely an autonomous executor.

Inputs:
- program policy
- current attack surface
- technologies
- completed tests
- failed tests with failure reasons
- identities available
- findings/hypotheses
- coverage gaps

Outputs:
- ranked next hypotheses
- recommended tool/test
- expected signal
- policy compatibility
- required identity
- approval class
- why the test is worth doing
- stopping condition

The first version should be deterministic + model-assisted and should never bypass policy.

### 4.3 Multi-Identity Engine — P0/P1

Proposed package:
`internal/identity`

Core entities:

```text
IdentitySet
├── anonymous
├── user-a
├── user-b
├── privileged-user
└── optional custom roles
```

Each identity carries:
- session material reference
- logical role
- owned object references
- authentication freshness
- CSRF/refresh metadata
- evidence-safe display name

Primary use cases:
- BOLA/IDOR differential testing
- BFLA / role boundary testing
- tenant/account isolation
- session invalidation
- ownership transfer checks
- privilege transition testing

Important: raw secrets should be stored behind references, not duplicated into blackboard text.

### 4.4 Evidence, Audit & Recovery — P0/P1

Proposed packages:
- `internal/evidence`
- `internal/recovery`

Evidence record must capture:
- immutable evidence ID
- campaign/finding/action IDs
- timestamp
- actor/identity alias
- policy version / decision ID
- request fingerprint
- response fingerprint
- sanitized request/response excerpts
- command/tool provenance
- screenshot/trace artifact references
- PoC linkage
- verification status
- redaction metadata
- integrity hash

Recovery checkpoint should persist:
- campaign state
- blackboard cursor
- pending cleanup
- identities by reference
- policy/scope version
- completed and skipped actions
- outstanding approvals

### 4.5 Workflow / Business-Logic Engine — P1

Proposed package:
`internal/workflow`

Represent target behavior as a state graph:

```text
state --action--> state
```

Examples:
- invite → accept → role change
- cart → coupon → checkout → refund
- password reset → token use → session invalidation
- create object → transfer ownership → access as previous owner
- subscription upgrade/downgrade → entitlement checks

Capabilities:
- infer candidate state transitions from browser/API traces
- record preconditions and identities
- propose legal test transitions
- identify invariant violations
- replay controlled sequences
- model race-condition candidates
- require stronger approvals for stateful/mutating tests

### 4.6 Target-Change Monitor — P1/P2

Proposed package:
`internal/monitor`

Track snapshots of:
- subdomains
- alive hosts
- endpoints
- parameters
- JavaScript assets/hashes
- API schemas
- technologies
- response fingerprints

Diffs should generate targeted guidance rather than automatically rescanning the entire program.

Example:
```text
new endpoint
  → classify auth requirement
  → compare against known roles
  → recommend targeted checks
```

### 4.7 HackerOne Reporting Assistant — P1

Extend `internal/bugbounty`.

Stages:
1. candidate finding
2. verified finding
3. duplicate analysis
4. report draft
5. operator review
6. submission-ready package
7. human-approved submission action (future/optional)

Duplicate fingerprint should use more than title:
- program
- asset
- endpoint/path
- HTTP method
- weakness/CWE
- parameter/object type
- root-cause signature
- affected role(s)
- evidence fingerprint
- CVE when relevant

## 5. Execution architecture

```text
                    HackerOne Program
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
      Structured Scope              Policy Text
             │                           │
             └─────────────┬─────────────┘
                           ▼
                Program Intelligence
                           │
                           ▼
                 Normalized Policy
                           │
                           ▼
                 POLICY GATEWAY
                           │
           ┌───────────────┼────────────────┐
           │               │                │
           ▼               ▼                ▼
       HTTP/API         Browser          Tools/MCP
           │               │                │
           └───────────────┼────────────────┘
                           ▼
                      Evidence Bus
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
           Swarm       Guidance     Identity Diff
              │            │            │
              └────────────┼────────────┘
                           ▼
                     Verification
                           │
                           ▼
                    Finding Graph
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
        Target Monitor            H1 Report Assistant
                                        │
                                        ▼
                                Human approval
```

## 6. First implementation sequence

### Phase 0 — Stabilize the inherited engine

Before increasing autonomy:
- reproduce and fix any swarm termination/quiescence defect
- enforce finite LLM/request/campaign timeouts
- ensure campaign API preserves submitted scope
- run existing unit/integration suites
- establish a known-good vulnerable-lab baseline

Exit criterion:
- a lab campaign always terminates
- blocked/unreachable scans report inconclusive rather than "clean"
- no target action can silently escape campaign scope

### Phase 1 — Universal Policy Gateway

Build:
- normalized policy model
- action classifier
- central decision API
- global rate limiter
- required-header injector
- disallowed-path matcher
- technique restriction matcher
- policy decision audit record

Integrate in this order:
1. built-in `httpreq`
2. exploit executor
3. browser
4. tool coordinator
5. MCP/plugin execution

Exit criterion:
- tests prove every target execution path hits the gateway
- policy denial cannot be overridden by an LLM/tool argument

### Phase 2 — Multi-Identity Differential Engine

Build:
- identity registry
- secure session references
- per-identity browser/HTTP context
- object ownership map
- normalized response comparator
- IDOR/BOLA/BFLA hypothesis generator

Exit criterion:
- lab test demonstrates object access comparison between two controlled users with reproducible evidence.

### Phase 3 — Evidence & Recovery

Build:
- evidence schema
- sanitization/redaction pipeline
- artifact hashing
- screenshot/network-trace references
- checkpoint/resume metadata
- cleanup ledger linkage

Exit criterion:
- a verified finding can be traced from report → evidence → action → identity → policy decision.

### Phase 4 — Hunter Guidance

Build:
- coverage map
- hypothesis queue
- recommended tool/test reasoning
- "why / expected signal / stop condition"
- approval-aware next-action suggestions

Exit criterion:
- for a selected authorized program, the CLI can explain what to test next without automatically executing it.

### Phase 5 — Workflow / Business Logic

Build:
- workflow graph
- pre/postcondition extraction
- stateful replay
- invariant rules
- race-test planning with strict rate/safety gates

Exit criterion:
- controlled lab workflows produce reproducible business-logic hypotheses and evidence.

### Phase 6 — Target Change Monitoring

Build:
- baseline snapshots
- diff engine
- change prioritization
- targeted re-test suggestions

Exit criterion:
- a changed endpoint/JS/API surface produces a bounded test plan rather than a whole-scope rescan.

### Phase 7 — HackerOne Reporting Assistant

Build:
- enhanced dedup fingerprints
- report evidence selection
- reproducibility checks
- CWE/CVSS mapping review
- report draft state machine
- explicit human approval gate

Exit criterion:
- produces a submission-ready draft with provenance and duplicate confidence, but does not auto-submit by default.

## 7. Proposed package layout

```text
internal/
├── policygateway/       # NEW
├── guidance/            # NEW
├── identity/            # NEW
├── evidence/            # NEW
├── recovery/            # NEW
├── workflow/            # NEW
├── monitor/             # NEW
│
├── scope/               # EXTEND
├── session/             # EXTEND
├── browser/             # EXTEND
├── bugbounty/           # EXTEND
├── agent/               # INTEGRATE, don't bypass policy
├── tools/               # INTEGRATE, don't bypass policy
├── swarm/               # PRESERVE adaptive engine
└── pipeline/            # EXTEND lifecycle/checkpoints
```

## 8. Upstream strategy

The fork should remain syncable with `Armur-Ai/Pentest-Swarm-AI`.

Rules:
- keep upstream-derived engine changes separable from Bug Bounty Swarm-specific features when practical
- prefer additive packages and interfaces over invasive rewrites
- record upstream commit SHA after each sync
- evaluate upstream security/safety changes before importing them
- never overwrite local policy/evidence invariants during an upstream merge
- preserve AGPL-3.0 license and upstream attribution

Suggested local remotes:

```bash
git remote -v
# origin   https://github.com/vesper-hq507/bug-bounty-swarm-ai.git
# upstream https://github.com/Armur-Ai/Pentest-Swarm-AI.git
```

## 9. Definition of "bug-bounty ready"

A campaign is not considered unattended-ready until all of these are true:

- policy is loaded and versioned
- scope is loaded and fail-closed
- global request-rate enforcement is active
- all execution paths are covered by the policy gateway
- explicit identity context is known
- secrets are stored by reference and redacted
- campaign has hard timeouts and a killswitch
- cleanup obligations are registered
- evidence provenance is enabled
- the operator can see skipped/blocked actions and why
- final report submission still requires explicit approval

## 10. Immediate engineering backlog

P0:
- universal policy gateway skeleton + tests
- central rate limiter
- policy/header/path enforcement
- execution-path coverage tests
- inherited swarm termination reliability
- global timeout/watchdog audit
- multi-identity data model

P1:
- differential authorization tester
- evidence provenance model
- recovery checkpoints
- browser workflow actions
- business-logic state graph
- hunter guidance CLI
- enhanced HackerOne dedup

P2:
- target-change monitor
- WebSocket/SSE coverage
- richer JavaScript/source-map analysis
- mobile application workflows
- optional human-approved HackerOne submission action
- public benchmark harness

Implementation checkpoint (2026-10-03): all P0/P1/P2 items above are implemented in the fork. External HackerOne posting remains opt-in and requires a previously approved, evidence-verified manifest plus an explicit send command and program-handle confirmation.

Post-roadmap pilot tooling (2026-10-03): HackerOne Opportunity Discovery is implemented as a zero-target-traffic operator aid. `pentestswarm opportunity discover` reads only public HackerOne opportunity/program pages, normalizes factual bounty/participation/response metrics, supports operator-selected filters and sorting, and never authorizes or starts testing. The researcher still selects the program and the existing scope → policy → preflight path remains mandatory before target traffic.

---

This document is the architectural source of truth for the fork until superseded by an accepted ADR. Implementation PRs should reference the relevant section and must preserve the safety invariants in Section 2.

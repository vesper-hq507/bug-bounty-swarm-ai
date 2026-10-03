# Controlled Bug-Bounty Benchmark

The public benchmark harness is a deterministic, offline regression suite for the bug-bounty fork.

## Purpose

The benchmark answers four questions that ordinary unit-test counts do not:

1. Does the system detect known positive security signals?
2. Does it stay quiet on paired negative controls?
3. Do policy, approval, and evidence boundaries fail closed?
4. Does the swarm terminate and recover predictably?

It is intentionally **not** a leaderboard for exploitation volume. The suite rewards precision, policy adherence, provenance, termination, and recovery.

## Run

```bash
pentestswarm benchmark controlled
pentestswarm --json benchmark controlled
```

The suite uses only in-process/static fixtures, local temporary files, and the in-memory swarm blackboard. It does not send requests to an Internet target.

## Controlled v1 matrix

The built-in suite contains paired positive/negative cases for:

- multi-identity BOLA/IDOR differential analysis
- workflow sequence/precondition analysis
- target-change monitor to Hunter Guidance
- JavaScript/client-code signal extraction
- HackerOne historical duplicate fingerprints

It also exercises:

- fail-closed policy path enforcement
- state-changing capability approval
- secret redaction and tamper-evident evidence
- durable recovery checkpoint reopen
- swarm quiescence completion
- context-cancellation termination

## Metrics

The report exposes:

- true positives / false positives / true negatives / false negatives
- precision
- recall
- false-positive rate
- policy-control pass rate
- evidence-control pass rate
- termination pass rate
- recovery pass rate

Controlled v1 deliberately uses strict default gates:

- precision = 1.0
- recall = 1.0
- false-positive rate = 0
- policy/evidence/termination/recovery = 1.0

These gates are regression expectations for deterministic fixtures, not claims about real-world vulnerability-detection rates.

## Safety

The benchmark is non-targeted. It does not authorize scanning a public program and does not weaken the universal policy gateway. A later external lab benchmark must remain explicitly opt-in and must use dedicated, locally controlled vulnerable applications.

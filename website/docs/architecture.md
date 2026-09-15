---
sidebar_position: 5
title: Architecture — Swarm vs. Pipeline
---

# Architecture: why a swarm beats a pipeline

Almost every "AI pentester" — and every tool that calls itself multi-agent — is
really a **pipeline**: a single planner LLM that walks a fixed line,
`recon → classify → exploit → report`, one stage at a time. It works, but it
inherits the pipeline's ceilings: it's **sequential**, it **can't react** to
something it finds three stages later, and its throughput is bounded by the
slowest stage.

Pentest Swarm AI is built differently. There is **no central planner**. Instead,
independent agents coordinate through a shared board and fire whenever the state
warrants it — so work happens **concurrently**, attack chains **emerge** instead
of being scripted, and the whole thing runs at machine speed.

## The pipeline model (what everyone else ships)

```
┌────────┐   ┌──────────┐   ┌─────────┐   ┌────────┐
│ recon  │──▶│ classify │──▶│ exploit │──▶│ report │
└────────┘   └──────────┘   └─────────┘   └────────┘
        one planner, one direction, one stage at a time
```

- **Sequential.** Stage N+1 waits for stage N to finish. A 1,000-endpoint
  surface is worked one bottleneck at a time.
- **No feedback.** If exploitation reveals a new object id or a fresh host, the
  pipeline has already left recon behind — there's no clean way to fold the
  discovery back in.
- **Central planner = single point of rigidity.** Adding a new capability means
  editing the orchestrator that sequences everything.

## The swarm model (what we ship)

```
        ┌───────────────── shared blackboard ─────────────────┐
        │   findings · object refs · pheromone weights (decay) │
        └───▲────────────▲───────────────▲───────────────▲─────┘
            │ read/write  │               │               │
        ┌───┴───┐   ┌─────┴────┐   ┌──────┴─────┐   ┌──────┴─────┐
        │ recon │   │ classify │   │  exploit   │   │   report   │
        └───────┘   └──────────┘   └────────────┘   └────────────┘
        each agent fires on its own trigger predicate, concurrently
```

Agents never call each other. They read and write a **shared blackboard**, and a
scheduler wakes whichever agent's **trigger predicate** matches the current board
state. Three swarm-intelligence primitives make it work:

### 1. Stigmergy — coordination through the environment

Ants don't hold meetings; they lay pheromone trails and follow the strong ones.
Our agents do the same. Every finding written to the board carries a **pheromone
weight** with a **half-life** — it spikes when written and **decays over time**.
Agents are biased toward high-weight findings, so:

- fresh, high-signal findings pull attention,
- stale paths **fade and die naturally** — no one has to prune them,
- different finding types decay at different rates (a live foothold stays hot
  longer than a low-severity banner).

Coordination is a property of the shared environment, not a controller.

### 2. Emergence — attack chains no one scripted

Because agents react to board state rather than a fixed script, multi-step
attacks **assemble themselves**:

> recon writes an endpoint → the classifier grades it high → that wakes the
> exploit agent → exploitation harvests an object id and writes it back →
> that wakes the exploit agent *again* on a new target → a proven finding wakes
> the report agent.

Nobody encoded "do BOLA after harvesting an id." The order **emerged** from what
was on the board. The exploit agent's adaptive object-reference sweep is a live
example: it harvests ids from earlier responses and **fans out** into dozens of
concurrent probes — a burst of work a linear plan would never have queued.

### 3. Decentralization — add an agent, not an orchestrator edit

Each agent owns its **trigger predicate** (e.g. "wake me for findings of type X
above pheromone Y"). To add a capability you write a new agent with its own
predicate and register it — it joins the swarm and starts reacting. **Nothing
rewrites a central planner**, because there isn't one.

## Why this is faster and finds more

| | Pipeline | Pentest Swarm |
|---|---|---|
| **Execution** | one stage at a time | dozens of agents + probes **concurrently** |
| **Reacting to new discoveries** | hard — recon already finished | automatic — a new finding wakes the right agent |
| **Attack chains** | fixed, pre-scripted order | **emergent** from board state |
| **Stale paths** | linger in the queue | **decay and die** via pheromones |
| **Adding capability** | edit the planner | drop in an agent + predicate |
| **Throughput** | bounded by the slowest stage | bounded by your concurrency + budget |

The practical payoff on stage: breadth. A pipeline gives you a tidy sequence; a
swarm gives you a **long list of proven findings** because many agents are
chewing on the surface at once and folding each discovery back in as they go.

## The cost question

Concurrency sounds expensive, but the expensive part — LLM reasoning — stays
bounded. The **fan-out is cheap work**: the hundreds of probes an exploit sweep
fires are plain HTTP requests, coordinated by a handful of LLM-driven agents.
Combined with [per-task model routing](./providers.md) and a hard
[spend cap](./cost-and-safety.md), a full run stays near the single-model
baseline (~$1) while doing far more than a linear pass.

## In the code

- **Blackboard** — `internal/swarm/blackboard`: shared findings, object refs, and
  pheromone weights with decay.
- **Scheduler** — `internal/swarm/scheduler.go`: concurrency caps, the budget
  enforcer, and trigger-predicate dispatch.
- **Agents** — `internal/swarm/agents`: recon, classifier, exploit (including the
  adaptive BOLA/IDOR sweep), and report, each with its own predicate.

:::tip
Watch it happen live. The [terminal TUI and web dashboard](./dashboard.md) render
the blackboard as a pulsing core with pheromone trails flowing between agents,
and show the exploit fan-out as a growing mesh of probe workers — the swarm
model, visualized in real time.
:::

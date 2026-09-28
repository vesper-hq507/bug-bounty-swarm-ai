# Pentest Swarm × Omnigent

Run **Pentest Swarm as a governed agent inside [Omnigent](https://omnigent.ai)** —
Databricks' open-source *meta-harness* for orchestrating AI agents.

## Both are harnesses — so how does this work?

They sit at **different layers**, and they nest.

- **Omnigent is a meta-harness.** It orchestrates other agents and enforces
  sandboxing, policies, credential brokering and cost controls *around* them. It
  treats each agent as a box it can launch, hand a task, and collect results from.
- **Pentest Swarm is a harness.** A purpose-built, multi-agent offensive one:
  recon → exploit → JEV grading → attack graph → report, coordinated over a
  shared blackboard.

```
Omnigent  (meta-harness — orchestrates + governs)
   │  "pentest this staging API, objective = account takeover"
   ▼
Pentest Swarm  (our harness — runs its own swarm of agents)
   ▼
structured findings / report  ──▶  back up to Omnigent
```

Omnigent has no "run an arbitrary CLI" executor — its agents are LLM harnesses
that call **tools**. Pentest Swarm already ships an **MCP server**
(`pentestswarm mcp serve`), so the manifest here wires that server in as a
`type: mcp` tool. Omnigent's reasoning brain then drives the swarm through it,
inside Omnigent's sandbox.

> Bonus: because this is just our MCP server, the *same* server also plugs into
> Claude Desktop, Cursor, and any MCP client — see `pentestswarm mcp serve`.

## Use it

1. Install the CLI and put it on `PATH`:
   ```bash
   npm i -g pentestswarm        # or: brew install armur-ai/tap/pentestswarm
   ```
2. Export keys:
   ```bash
   export PENTESTSWARM_ORCHESTRATOR_API_KEY=...   # the swarm's orchestrator
   export ANTHROPIC_API_KEY=...                   # the agent's reasoning brain
   ```
3. Run the agent through Omnigent:
   ```bash
   omnigent run integrations/omnigent/pentest-swarm.yaml
   ```
   …or reference the `pentest-swarm` agent from a larger multi-agent Omnigent
   session, so an offensive-security specialist joins your other agents under
   one governed roof.

## Governance you get for free

Omnigent wraps the swarm in its sandbox (`os_env.sandbox`): outbound network is
allowed (the swarm must reach the target in scope), `./reports` is writable for
artifacts, and everything else is isolated. Pin `egress_rules` to your
authorized scope for defense-in-depth — the sandbox then can't reach anything
you didn't approve, on top of the swarm's own scope validation.

## Swap the brain

The manifest defaults to the `claude-sdk` harness. Omnigent also supports
`openai-agents`, `codex`, `cursor`, `antigravity` (Gemini), `qwen`, `kimi` and
more — change `executor.harness` and `executor.auth` to use a different model as
the operator driving the swarm.

Field names follow Omnigent's `docs/AGENT_YAML_SPEC.md`; validate against your
Omnigent version before production use.

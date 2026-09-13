---
sidebar_position: 4
title: CLI Reference
---

# CLI Reference

Everything Pentest Swarm AI does is available from the `pentestswarm` binary.
There are two ways in: **`run`** (the interactive front door) and **`scan`**
(the scriptable engine underneath it).

## `run` vs `scan`

- **`pentestswarm run`** is the **front door**: an interactive TUI launcher.
  Pick your provider and paste a key in the UI, choose a target or a bundled
  lab, pick your live view, and launch — **no flags to remember**. It runs
  readiness checks for you and then calls `scan` under the hood.
- **`pentestswarm scan …`** is the **engine**: fully flag-driven and
  scriptable, so it drops straight into CI, cron, or a shell script. `run` is
  just a friendly wrapper around it.

Use `run` when you're driving it by hand; use `scan` when you're automating.

## Commands

### `pentestswarm run`

⭐ Interactive TUI launcher — the recommended starting point. Walks you through
provider + key, target or bundled lab, live-view choice, and readiness checks,
then launches the swarm.

```bash
pentestswarm run
```

### `pentestswarm scan <target> --scope <scope> --swarm`

Run a scan against a target. `--scope` constrains what the swarm is allowed to
touch (enforced at the tool layer *and* the executor). `--swarm` enables the
stigmergic swarm scheduler.

```bash
export PENTESTSWARM_ORCHESTRATOR_API_KEY=your-key
pentestswarm scan example.com --scope example.com --swarm --follow
```

Useful flags:

- `--scope <scope>` — the authorized scope; not bypassable.
- `--swarm` — enable the stigmergic swarm scheduler.
- `--provider <name>` — pick the LLM provider (see [Providers](./providers.md)).
- `--follow` — stream progress to the terminal.

### `pentestswarm scan --tui`

Run with the **full-screen live dashboard** in your terminal — live charts, a
swarm-topology diagram, and a graded findings stream.

```bash
pentestswarm scan <target> --scope <target> --swarm --tui
```

### `pentestswarm scan --lab --lab-target <lab>`

Attack a bundled, intentionally-vulnerable lab that spins up, gets attacked, and
tears down — no setup, no external target. Requires Docker.

```bash
pentestswarm scan --lab --lab-target crapi --provider ollama --swarm --tui
```

Labs: `crapi`, `juiceshop`, `vampi`, `dvga`.

### `pentestswarm playbook run <name> --target <t>`

Run a deterministic attack chain (a playbook) against a target. See
[Playbooks](./playbooks.md).

```bash
pentestswarm playbook run bug-bounty --target example.com
```

### `pentestswarm doctor`

System health check — verifies Go, Docker, installed recon tools, and provider
configuration, and tells you what (if anything) to fix.

```bash
pentestswarm doctor
```

### `pentestswarm install-tools`

Fetch the recon / exploit toolchain (subfinder, httpx, nuclei, naabu, katana,
dnsx, gau, nmap, …) so the swarm has real tools to operate.

```bash
pentestswarm install-tools
```

### `pentestswarm mcp serve`

Start the MCP (Model Context Protocol) server so Claude Desktop, Cursor, and
other MCP clients can drive the swarm as a tool.

```bash
pentestswarm mcp serve
```

### `pentestswarm serve`

Start the API server together with the web dashboard.

```bash
pentestswarm serve
```

## Quick tour

```bash
pentestswarm run                                        # ⭐ Interactive TUI — no flags
pentestswarm scan <target> --scope <scope> --swarm      # Scriptable swarm scan
pentestswarm scan <target> --scope <scope> --tui        # Full-screen live dashboard
pentestswarm scan --lab --lab-target crapi              # Attack a bundled lab
pentestswarm playbook run <name> --target <t>           # Run a playbook
pentestswarm doctor                                     # Health check
pentestswarm install-tools                              # Fetch the toolchain
pentestswarm mcp serve                                  # MCP server (Claude / Cursor)
pentestswarm serve                                      # API server + dashboard
```

---
sidebar_position: 7
title: Reducing false positives (Jev)
---

# Reducing false positives (Jev)

Every autonomous scanner produces some false positives. Pentest Swarm AI already
grades and de-duplicates findings before it writes the report — but you can add
one more pass that drops findings a second, independent model is confident are
**not** real. That optional pass is **Jev**.

[Jev](https://typesafe.ai) is TypeSafe's *"System One"* model. It is **not an
LLM** — instead of generating text, it returns **typed, probabilistic
decisions** in a single fast, cheap pass. Pentest Swarm AI asks it one yes/no
question per finding — *"is this a real, exploitable vulnerability?"* — and gets
back a probability for each. Findings below the threshold are removed.

:::note This is opt-in and off by default
The swarm's own grading is the primary quality control. Jev is a **second
opinion** for teams who want to trim the last of the noise before triage. If you
don't turn it on, nothing changes.
:::

## Turning it on

You need a TypeSafe API key — get one at **[typesafe.ai](https://typesafe.ai)**.
Provide it via the `TYPESAFE_API_KEY` environment variable (preferred) or the
`--jev-key` flag.

### In the launcher (`pentestswarm run`)

The interactive launcher has a **Jev FP filter** toggle, off by default. Switch
it on with the arrow keys. If `TYPESAFE_API_KEY` isn't already set, a masked
**TypeSafe key** field appears for you to paste the key into; when the env var is
present, the launcher uses it and skips the field.

### On the command line

```bash
export TYPESAFE_API_KEY=your-typesafe-key
pentestswarm scan example.com \
  --scope example.com \
  --swarm --follow \
  --jev
```

Or pass the key inline:

```bash
pentestswarm scan example.com --scope example.com --swarm --jev --jev-key your-typesafe-key
```

## How it behaves

- **Where it runs.** As the **final step of the report agent** — *after* the
  swarm's findings are graded and duplicates are collapsed, and just *before* the
  report is rendered. It sees the clean, de-duplicated set.
- **What it drops.** Each surviving finding is scored `0.0–1.0` for
  *P(real vulnerability)*. Anything below the threshold (**default `0.5`**) is
  dropped. You'll see a campaign event like:

  > `Jev false-positive filter: kept 7, dropped 2 (P(real) < 0.50)`

- **It fails OPEN.** If the Jev API errors, times out, or is unreachable, the
  filter is **skipped and every finding is kept**. A transient hiccup will never
  silently discard a real bug — you'll see a
  `Jev false-positive filter skipped … — keeping all N findings` event instead.
- **Preflight.** When `--jev` is set, the run checks the key up front. A missing
  key stops the run with a clear message; a bad key fails the Jev health check
  fast, so you find out immediately rather than at report time.

## Cost

Jev is billed by TypeSafe, **separately** from your LLM provider. It's a single
typed pass over the final finding set (not per-token generation), so it's cheap
and doesn't count against your [spend cap](./cost-and-safety.md#spend-cap), which
only meters LLM spend.

:::tip Why not LiteLLM / an OpenAI-compatible endpoint?
Jev isn't a chat model, so it doesn't fit the OpenAI-compatible provider path the
[other providers](./providers.md) use. Pentest Swarm AI talks to its typed
`/v1/systemone` API directly — no LiteLLM or extra proxy required.
:::

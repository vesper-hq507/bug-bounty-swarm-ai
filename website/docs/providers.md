---
sidebar_position: 3
title: LLM Providers
---

# LLM Providers

Pentest Swarm AI is the **harness, not the model**. Point it at whichever LLM
you want — a frontier cloud model, an open cyber-benchmark leader, or a fully
local one.

:::tip One key, whole swarm
All agents inherit from a **single** provider config. Set one provider and one
key, and the entire swarm — orchestrator plus every agent — uses it. There is no
per-agent key wrangling.
:::

## Setting the key

For any cloud provider, the API key is read from an environment variable (or set
in the launcher UI / config file):

```bash
export PENTESTSWARM_ORCHESTRATOR_API_KEY=your-key-here
```

Select the provider with the `--provider` flag on `scan`, in `pentestswarm run`,
or in your config's `orchestrator.provider`.

## Supported providers

| Provider | `--provider` | Key needed | Notes |
|----------|--------------|------------|-------|
| Together AI | `together` | yes | Hosted Llama / Qwen / DeepSeek / GLM; key from [api.together.xyz](https://api.together.xyz) |
| Claude | `claude` | yes | Anthropic; best quality, prompt caching |
| OpenAI | `openai` | yes | OpenAI **and any OpenAI-compatible endpoint** |
| Gemini | `gemini` | yes | Google; large context, free tier available |
| OrcaRouter | `orcarouter` | yes | One gateway for Claude / GPT + other frontier models |
| Ollama | `ollama` | **no** | 100% local, air-gapped |
| LM Studio | `lmstudio` | **no** | 100% local, GUI model management |

### Together AI

Hosted, low-cost access to the open models topping the cyber-offense
benchmarks — Llama, Qwen, DeepSeek, and GLM.

```bash
export PENTESTSWARM_ORCHESTRATOR_API_KEY=your-together-key
pentestswarm scan <target> --scope <target> --provider together --swarm
```

Get a key at [api.together.xyz](https://api.together.xyz). Under the hood
Together speaks the OpenAI Chat-Completions API, so you can also drive it via
the generic `openai` provider with the endpoint `https://api.together.xyz/v1`.

### Claude (Anthropic)

```bash
export PENTESTSWARM_ORCHESTRATOR_API_KEY=sk-ant-...
pentestswarm scan <target> --scope <target> --provider claude --swarm
```

Best out-of-the-box quality, and prompt caching is enabled by default for the
recon and classifier agents to cut cost and latency.

### OpenAI (and any OpenAI-compatible endpoint)

The `openai` provider works with OpenAI itself and **any** service that exposes
a Chat-Completions `/v1` API — DeepSeek, Groq, Together, and more. The only hard
requirement is native tool / function calling. Point it at the vendor's base URL
in your config (`orchestrator.endpoint`) and set the key.

```yaml
orchestrator:
  provider: "openai"
  endpoint: "https://api.together.xyz/v1"
  model: "zai-org/GLM-5.3"     # or Qwen/..., deepseek-ai/..., etc.
  api_key: ""                   # or export PENTESTSWARM_ORCHESTRATOR_API_KEY
  context_window: 128000
```

### Gemini

```bash
export PENTESTSWARM_ORCHESTRATOR_API_KEY=AIza...
pentestswarm scan <target> --scope <target> --provider gemini --swarm
```

Large context window and a free tier — get a key from
[Google AI Studio](https://aistudio.google.com/apikey).

### OrcaRouter

A single gateway endpoint that fronts Claude, GPT, and other frontier models
with gateway-level security.

```bash
export PENTESTSWARM_ORCHESTRATOR_API_KEY=sk-orca-...
pentestswarm scan <target> --scope <target> --provider orcarouter --swarm
```

## Local providers (no key, no cloud)

For full privacy and zero API cost, run the swarm entirely on your own machine.
**No API key is required** for either of these.

### Ollama

```bash
# install Ollama and pull a tool-calling model, then:
pentestswarm scan <target> --scope <target> --provider ollama --swarm
```

### LM Studio

Load a model in LM Studio, enable its local server, then:

```bash
pentestswarm scan <target> --scope <target> --provider lmstudio --swarm
```

:::note Tool calling required
Whatever model you choose — local or hosted — must support native tool /
function calling. That's what lets the swarm actually *operate* tools rather
than just describe them.
:::

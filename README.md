# kirmizi-recon

**AI Red Teaming Recon Agent** — a Claude-driven agent that performs *hybrid*
reconnaissance on a target: the **AI application** (model fingerprinting,
guardrail/refusal mapping, prompt-leak indicators, exposed tools, injection
surface) **and** its surrounding **infrastructure / OSINT** (DNS, subdomains,
port/service enumeration, API/endpoint enumeration, HTTP/TLS fingerprinting,
RDAP). It produces a structured `ReconReport` intended
to feed downstream agents (attack planning, exploitation) in a future
multi-agent AI red-teaming platform — initially via direct calls, eventually
over **A2A**.

This is authorized security-testing tooling. It is **passive by default**;
anything that sends traffic to the target ("active") is gated behind explicit
scope authorization.

## Design

```
ReconAgent.run(target: ReconTarget, scope: ReconScope) -> ReconReport
```

- **Two-phase: deterministic collect → agentic analyze.** A deterministic
  `collect()` phase (`collector.py`) runs the broad scans in plain code — no LLM
  — producing a structured `Evidence` bundle (fast, reproducible, no API key,
  runnable standalone via `--collect-only`). The agentic `analyze()` phase is
  *seeded* with that evidence and only does judgment work: interpretation,
  **adaptive** `ai_probe` of the AI app, bounded targeted follow-up scans, and
  report synthesis. The model reasons; it doesn't schedule fixed scans.
  `Evidence` is also the clean seam for a future A2A collector → analyst split.
- **Interface-agnostic core** (`agent.py`): `run()` = collect + analyze;
  `collect()` and `analyze()` are also callable independently. The CLI uses them
  today; an A2A `AgentExecutor` can wrap them later. `ReconTarget` (in) /
  `ReconReport` (out) are the stable contract.
- **Claude is the judge, tools are data-gatherers.** Tools return raw evidence
  (DNS records, HTTP headers, TLS certs, target AI responses); Claude does the
  interpretation (model family, guardrails, prompt leakage).
- **Manual agentic loop** (analyze phase) for deterministic control over scope
  enforcement, active-action gating, rate limiting, and `pause_turn` resumption.
- **Structured output** via a strict `finalize_report` tool derived from the
  report schema.

## Install

```bash
python -m venv .venv && source .venv/bin/activate   # Python 3.10+
pip install -e ".[dev]"
# Auth: export ANTHROPIC_API_KEY=...   (or run `ant auth login`)
```

**nmap (recommended).** The `port_scan` tool uses `nmap -sV` for real
service/version enumeration when the `nmap` binary is on `PATH`. Without it, it
falls back to a pure-Python TCP connect scan (open ports + light banners, **no
version detection**), and results are labeled `degraded`. For trustworthy
service enumeration, install nmap (or bundle it in your container image).

## Usage

Passive recon (no traffic to the target):

```bash
python -m kirmizi-recon -d example.com
# or, once installed as a script:
kirmizi-recon -d example.com
```

Deterministic collection only — the scan pipeline with **no LLM / no API key**,
emitting the raw `Evidence` bundle as JSON:

```bash
kirmizi-recon -d example.com --collect-only
kirmizi-recon -d acme.example.com --active --auth "SOW-1" --collect-only --out reports/acme
# writes reports/acme.evidence.json
```

Active recon — requires the `--active` flag **and** an authorized scope:

```bash
kirmizi-recon \
  -d acme.example.com \
  -e https://acme.example.com/chat \
  --active \
  --auth "PENTEST-1234 / signed SOW 2026-08"
```

Or drive everything from an engagement file (see `engagement.example.yaml`):

```bash
kirmizi-recon --engagement engagement.yaml --out reports/acme
# writes reports/acme.recon.json and reports/acme.recon.md
```

### The two gates for active recon (fail-closed)

Active actions require **both**:

1. **Intent** — the `--active` flag (or `mode: active` in the engagement file).
2. **Permission** — the specific target is in scope (`--in-scope` / `in_scope`,
   or auto-derived from the `--domain`/`--ai-endpoint` you named). Scope entries
   can be hostnames (`acme.example.com`, `*.acme.example.com`), bare IPs, or
   CIDRs (`203.0.113.0/24`). Port scans resolve the host and authorize the
   resulting IP against these entries.

Plus a **non-empty `authorization`** reference (unless `--trust-local` for
localhost/RFC-1918 targets you own). Requests are rate-limited
(`--rate`, default 2/s) and budgeted (`--max-active`, default 200). An
out-of-scope active call is refused and surfaced to the agent as an error — the
run continues with passive means instead of crashing.

### `authorization` / SOW vs. model restrictions

The `authorization` field records who authorized the test; it drives **our**
scope enforcement and audit trail. It does **not** lift Anthropic's safety
classifiers — those run at the API layer regardless of any prompt claim, and it
is not a bypass. The agent stays inside model policy by being scoped to **recon
and analysis only** (never exploit/payload generation). Engagement context is
injected into the system prompt as honest authorized-testing framing, which
legitimately reduces false-positive refusals; `stop_reason == "refusal"` is
handled and server-side `fallbacks` re-serve benign requests that still trip a
classifier.

## Local end-to-end test

```bash
python tools/mock_target.py 8799        # terminal 1
kirmizi-recon --active --trust-local \
  -e http://127.0.0.1:8799/chat -d 127.0.0.1   # terminal 2
```

## Tests

```bash
pytest        # scope enforcement, schema, tool parsers (no live network)
```

## Endpoint wordlist

`endpoint_scan` probes a curated ~385-path wordlist (`kirmizi_recon/wordlists/`)
covering AI/LLM inference APIs (OpenAI-compatible, Ollama, HF TGI, vLLM, Triton,
TensorFlow Serving, MLflow, LangServe, Anthropic, MCP/Gradio), auth, API
docs/OpenAPI, GraphQL IDEs, Spring Boot Actuator, admin/debug consoles,
`.well-known` (OIDC/OAuth/AI-plugin/MCP) manifests, and source/secret exposure.
The base list came from this project's original endpoint scanner and was
augmented with high-value paths from
[chrislockard/api_wordlist](https://github.com/chrislockard/api_wordlist) and
[danielmiessler/SecLists](https://github.com/danielmiessler/SecLists). The agent
can also pass `extra_paths`, or you can supply your own list via
`wordlists.load_wordlist()`.

## A2A roadmap

`ReconAgent.run` is the handler a future A2A `AgentExecutor` will wrap;
`ReconTarget` maps to an incoming A2A message and `ReconReport` serializes as an
A2A artifact. Intended Agent Card skills: `infra-recon`, `ai-recon`. No A2A
dependency is added yet — the core is already shaped for it.

## Layout

```
kirmizi_recon/
  agent.py     # ReconAgent: run() = collect + analyze; analyze() is the agentic loop
  collector.py # deterministic collection phase (collect() -> Evidence)
  schemas.py   # ReconTarget / ReconScope / ReconReport (the contract)
  scope.py     # fail-closed enforcement + rate limiter
  prompts.py   # cached system prompt (engagement framing)
  config.py    # settings (model, effort, ...)
  report.py    # ReconReport -> json/markdown
  cli.py       # typer CLI over the core
  tools/       # infra (DNS/CT/RDAP/port_scan/endpoint_scan/HTTP/TLS), ai_target (ai_probe), report (finalize)
  wordlists/   # curated API/endpoint wordlist used by endpoint_scan
tools/mock_target.py   # local mock AI endpoint for e2e
```

# Sesame

[English](README.md) | [简体中文](README_zh.md)

Sesame is a test-enablement system for rehosted IoT firmware. When firmware is rehosted into an emulator (e.g. QEMU), most of its web surface — admin pages, CGI endpoints, APIs — sits behind an authentication gate that blocks downstream analysis and fuzzing.

Sesame uses an LLM-driven agent to **recover the authentication dependency state** (login flow, default credentials, session cookies/tokens) so that auth-gated pages and services become testable, improving rehosting metrics and expanding the effective surface for fuzzing. Breaking authentication is not the end goal — re-enabling testing is.

## How It Works

Sesame runs a 4-phase pipeline orchestrated around an LLM agent with filesystem tools (`search_files`, `read_file`, `grep_files`) and runtime tools (`http_request`, `browser_navigate`):

| Phase | What happens |
|-------|--------------|
| **Pre-process** | Automatically decompiles Fate/Z encrypted Lua files (Xiaomi/MIWiFi) with the bundled `unluac_miwifi` |
| **1 · Surface Discovery** | Static rootfs analysis: web binaries, CGI handlers, frontend assets, config sources, JavaScript dispatch tables (e.g. `topicurl.js`), plus a knowledge base of vendor auth patterns (TOTOLINK, Xiaomi, D-Link, TP-Link, …) |
| **2 · Semantic Analysis** | A 3-stage LLM pipeline: **Stage 1** explores the filesystem to identify the auth architecture, login URL/method/params, session mechanism and credential storage; **Stage 2** reasons about why auth gating blocks testability, classifying mismatches into source / representation / transfer / consumption layers; **Stage 3** autonomously executes recovery via runtime tools — login attempts, credential reset, session token capture, browser-driven flows |
| **3 · Mismatch Localization** | Combines LLM-identified mismatches with heuristic fallback findings, ranks recovery hypotheses |
| **4 · Verification & Fuzz Enablement** | Re-evaluates target reachability with the recovered session state and generates fuzz artifacts seeded with cookies/tokens; an execution agent can replay the recovery plan inside the QEMU VM |

Each discovered target is graded on a reachability ladder: `unreachable → login_page → post_auth_page → api_ready → fuzz_ready`.

## Installation

Requirements: Python ≥ 3.10, [Java runtime](https://adoptium.net/) (only needed for Lua decompilation on Xiaomi firmware).

```bash
pip install -e .
playwright install chromium   # for browser-driven auth recovery
```

## Quick Start

1. Configure LLM access (optional — without a key, Sesame falls back to heuristic analysis):

```bash
cp .env.example .env
# edit .env and set SESAME_DEEPSEEK_API_KEY
```

2. Point Sesame at an extracted firmware rootfs that is already being served by your rehosting environment:

```bash
python -m sesame audit \
  --rootfs /path/to/squashfs-root \
  --web http://10.10.10.2
```

Add `--json` for machine-readable output, or use the installed entry point (`sesame audit …`).

Sesame prints before/after rehosting metrics, per-target reachability with blockers, mismatch hypotheses, recovery plans, and generated fuzz artifacts; a structured run summary is appended to `logs/`.

## Configuration

All settings are environment variables (loaded from `.env`, all optional):

| Variable | Default | Description |
|----------|---------|-------------|
| `SESAME_DEEPSEEK_API_KEY` | *(empty)* | DeepSeek API key; empty → heuristic-only mode |
| `SESAME_DEEPSEEK_API_BASE` | *(empty)* | Custom API base URL |
| `SESAME_DEEPSEEK_MODEL` | `deepseek-v4-pro` | Model name |
| `SESAME_DEEPSEEK_TEMPERATURE` | `0.0` | Sampling temperature |
| `SESAME_DEEPSEEK_THINKING` | `true` | Enable reasoning mode |
| `SESAME_HTTP_TIMEOUT` | `8.0` | HTTP probe timeout (seconds) |
| `SESAME_MAX_CONTEXT_CHARS` | `8000` | Max characters per file read into LLM context |
| `SESAME_MAX_TARGETS` | `128` | Max targets analyzed per run |
| `SESAME_DEBUG` | `false` | Verbose logging |

## Tested Results

### TOTOLINK NR1800X (MIPS, lighttpd + cstecgi.cgi)

| Metric | Before | After |
|--------|--------|-------|
| Reachable pages | 1 | 17 |
| Post-auth targets | 0 | 137 |
| Fuzz-ready targets | 0 | 12 |

### Xiaomi BE3600 Pro (ARM, nginx + uhttpd/LuCI)

| Metric | Result |
|--------|--------|
| Total targets discovered | 21 |
| Fate/Z Lua files decompiled | 228 |

## Project Structure

```text
sesame/
├── browser/           # Playwright driver + firmware web UI analyzer
├── connectors/        # HTTP probe + QEMU shell connector (SSH/serial/telnet)
├── discovery/         # Surface discovery, vendor auth knowledge, Lua decompiler
├── domain/            # Data models (surface, report, mismatch, llm_result)
├── execution/         # Recovery-plan execution agent (QEMU VM, retry logic)
├── primitives/        # Recovery primitives
├── reasoning/         # Mismatch localization, hypothesis ranking, plan composition
├── semantics/         # LLM agent pipeline (orchestrator, stages, agent tools)
├── utils/             # Logger, cache, unluac_miwifi Lua decompiler
├── verification/      # Reachability evaluation + fuzz artifact generation
├── bootstrap.py       # Settings (.env loading)
├── cli.py             # Typer CLI with Rich output
├── config.py          # Runtime bundle factory
└── pipeline.py        # Main pipeline entry point
```

## Documentation

- [docs/design_zh.md](docs/design_zh.md) — research framing, innovation points, evaluation design (Chinese)
- [docs/implementation_zh.md](docs/implementation_zh.md) — architecture, pipeline, models, engineering details (Chinese)

## Responsible Use

Sesame is a security research tool intended for analyzing firmware in **local, emulated environments that you own or are authorized to test**. Do not use it against live devices or services without explicit permission from their owners.

## Third-Party Components

- [unluac](https://sourceforge.net/projects/unluac/) (bundled as `sesame/utils/unluac_miwifi`, MIT license) — modified for Fate/Z encrypted Lua; see its `license.txt`

## License

Released under the [MIT License](LICENSE).

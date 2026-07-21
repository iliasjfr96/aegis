# Aegis — Automated Multi-Agent Red Team for LLM Applications

![CI](https://github.com/iliasjfr96/aegis/actions/workflows/ci.yml/badge.svg)
![Tests](https://img.shields.io/badge/tests-38%20passed-brightgreen)
![Python](https://img.shields.io/badge/python-3.12-blue)
![License](https://img.shields.io/badge/license-MIT%20(authorized--use)-orange)

> 📸 **Demo screenshots**: see `docs/` — dashboard, attack timeline, and a real
> audit report against a live Kimi-powered target (3 findings incl. 1 CRITICAL).

Aegis audits LLM applications (chatbots, RAG systems, agents) the way a security
firm would: it **reconnoiters** the target, **plans** attack techniques
adaptively, **executes** multi-turn attacks, **proves** vulnerabilities with
deterministic canary tokens + an LLM judge, and delivers a **professional
HTML audit report** with OWASP LLM Top 10 mapping and remediations.

> Authorized testing only — Aegis refuses any target outside its whitelist.

## Architecture

```
scope_guard → recon → plan ⇄ attack → evaluate → report
     │           │       │        │        │         │
  whitelist   3 benign  adaptive multi-turn  canary  HTML report
  enforced    probes →  technique attacks   + LLM   + dashboard
  at network  TargetProfile selection      judge
  boundary
```

- **Orchestration**: LangGraph (typed state, conditional loops, budget guardrails)
- **LLMs**: provider-agnostic — Ollama (local, free) by default; **Kimi Code
  subscription** (billed via membership, not per-token); OpenAI/Anthropic via env
- **Detection**: canary tokens (deterministic) + LLM-as-judge with OWASP severity scoring
- **Integration**: 3 MCP servers (target connector, payload library, report writer)
- **Observability**: Langfuse traces per graph node (self-hosted, included in compose)

## Vulnerable demo target (included)

`HR-Bot`, an internal HR assistant with **3 progressive defense levels**:

| Level | Defenses | Expected Aegis result |
|-------|----------|----------------------|
| 0 | none | system prompt leak, RAG data exfiltration, tool abuse (email/file) |
| 1 | naive word blocklist | blocks frontal injection, still leaks via polite RAG queries |
| 2 | input filter + output canary scrubber + ACL on retrieval + tool allowlist | resists — honest "no findings" report |

## Beyond chatbots: web & WebSocket audits

Aegis also audits apps with NO chatbot at all - deterministically, zero LLM
quota consumed:

```
POST /webscan {"target_url": "https://your-app.com",
               "jwt_token": "optional-jwt-to-audit",
               "ws_url": "ws://your-app.com/ws"}
```

- **Web surface**: security headers (CSP, HSTS...), CORS (wildcard+credentials,
  reflected origins), exposed files (`.env`, `.git`), cookie flags
- **JWT**: alg=none, weak HMAC secrets (offline brute-force), missing expiry
- **WebSocket** (realtime apps, games): unauthenticated event emission,
  malformed-frame resilience, flood/rate-limit probing

## Quick start (Docker, one command)

```bash
docker compose up --build
# Dashboard  → http://localhost:5173
# API        → http://localhost:8200
# Targets    → :8100 (level 0)  :8101 (level 1)  :8102 (level 2)
# Langfuse   → http://localhost:3100 (create a project, paste keys into .env)
```

Then in the dashboard, launch an audit against `http://localhost:8100`
(from inside compose, the API also accepts `http://target-l0:8100`).

## Local development

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
ollama pull llama3.1:8b            # free local models (or set OpenAI/Anthropic keys)
cp .env.example .env
./scripts/run_demo.sh              # 3 targets + API + dashboard
.venv/bin/python -m pytest tests/  # 38 tests
```

## Using your Kimi Code subscription

Aegis can run entirely on a Kimi membership (no per-token API billing):

```bash
# .env
AEGIS_LLM_PROVIDER=kimi
KIMI_API_KEY=<key from the Kimi Code Console>   # https://www.kimi.com/code
AEGIS_ATTACK_MODEL=kimi-for-coding              # all members
AEGIS_JUDGE_MODEL=k3                            # Moderato tier and above
```

The Kimi Code endpoint is OpenAI-compatible (`https://api.kimi.com/coding/v1`)
and rate-limited per plan (~300–1,200 requests / 5h) — comfortably enough for
full audits, since Aegis caps requests via `AEGIS_MAX_TOTAL_REQUESTS` anyway.

## MCP servers

```bash
python -m aegis.mcp_servers.target_connector   # chat with whitelisted targets
python -m aegis.mcp_servers.payload_library    # attack techniques & openers
python -m aegis.mcp_servers.report_writer      # render HTML audit reports
```

## Safety design

- Target whitelist enforced at the network boundary (`TargetClient`) — an agent
  cannot reach a non-approved URL even if the LLM hallucinates one
- Request budget caps (`AEGIS_MAX_TOTAL_REQUESTS`) against runaway loops
- Tool side effects in the demo target are sinks (emails are recorded, not sent)

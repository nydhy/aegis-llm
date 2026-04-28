# aegis-llm

A drop-in security proxy for any OpenAI-compatible LLM endpoint. Sits between your client and the upstream model, running every request through a six-layer threat pipeline before forwarding it.

## Try it — no LLM required

Demo mode starts an in-process stub backend so you can explore the pipeline without any external dependencies.

```bash
# terminal 1 — start the proxy in demo mode
DEMO_MODE=true go run ./cmd/server

# terminal 2 — open the UI
cd demo && npm install && npm run dev
```

Then open `http://localhost:5173`. Use the preset buttons to fire clean and jailbreak prompts and watch the security layers respond in real time.

## How it works

```mermaid
flowchart TD
    A([Client Request]) --> B[Auth check\nBearer token optional]
    B -->|invalid key| Z1([401 Unauthorized])
    B -->|ok| C

    C[Layer 1 · Penalty box\nIs this fingerprint flagged?]
    C -->|flagged| Z2([429 Too Many Requests])
    C -->|clear| D

    D[Layer 2 · RPM rate limit\nRequests per minute per user]
    D -->|exceeded| Z3([429 Too Many Requests])
    D -->|ok| E

    E[Layer 3 · Regex scan\nRole hijacking · instruction override\ninjection tokens · token stuffing]
    E -->|matched| Z4([403 Forbidden\nuser flagged in penalty box])
    E -->|clean| F

    F[Layer 4 · Shannon entropy\nDetects obfuscated / encoded payloads]
    F -->|HIGH| Z5([403 Forbidden\nuser flagged in penalty box])
    F -->|SUSPICIOUS| G
    F -->|CLEAN| H

    G[Layer 5 · LLM judge\nOptional · disabled by default]
    G -->|BLOCK| Z6([403 Forbidden\nuser flagged in penalty box])
    G -->|ALLOW / disabled| H

    H[Layer 6 · Token budget\nSliding window per user per hour]
    H -->|exceeded| Z7([429 Too Many Requests])
    H -->|ok| I

    I[Forward to upstream LLM\nstream or non-stream]
    I --> J[Record output tokens\nagainst budget]
    J --> K([200 · response + aegis metadata])
```

Every blocked response includes an `aegis` metadata object describing the threat level, entropy score, tokens used, and block reason.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness check; reports judge status |
| GET | `/v1/models` | Proxied to upstream |
| POST | `/v1/chat/completions` | Chat — full pipeline + streaming support |
| POST | `/v1/embeddings` | Proxied to upstream (no pipeline analysis) |

## Configuration

Copy `.env.example` and adjust:

```env
# Proxy LLM — any OpenAI-compatible endpoint
LLM_BASE_URL=http://localhost:11434/v1   # Ollama, Groq, OpenAI, …
LLM_API_KEY=
LLM_MODEL=llama3

# Optional LLM judge for SUSPICIOUS entropy prompts (disabled by default)
JUDGE_ENABLED=false
JUDGE_BASE_URL=      # defaults to LLM_BASE_URL
JUDGE_API_KEY=
JUDGE_MODEL=llama3

# Entropy thresholds
ENTROPY_HIGH_THRESHOLD=6.5
ENTROPY_SUSPICIOUS_THRESHOLD=5.5

# Rate limits
RATE_LIMIT_RPM=60
TOKEN_BUDGET_PER_HOUR=50000

# Penalty box TTL
PENALTY_TTL_MINUTES=60

# Optional: protect the proxy itself
# AEGIS_API_KEY=your-secret-key
```

## Running

```bash
go run ./cmd/server
```

Point your LLM client at `http://localhost:8080` instead of the upstream directly.

## Pipeline layers

| # | Layer | Trigger | Response |
|---|-------|---------|----------|
| 1 | Penalty box | Prior violation TTL active | 429 |
| 2 | RPM rate limit | Requests/min per fingerprint | 429 |
| 3 | Regex scan | Role hijacking, instruction override, injection tokens (Llama/ChatML/Alpaca), token stuffing | 403 + penalty |
| 4 | Shannon entropy | Score above `ENTROPY_HIGH_THRESHOLD` | 403 + penalty |
| 5 | LLM judge | Score between thresholds, judge enabled | 403 + penalty |
| 6 | Token budget | Hourly token window exhausted | 429 |

User fingerprints are derived from `X-User-ID` header + client IP. Flagged users are held in an in-memory penalty box with a configurable TTL.

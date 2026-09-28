# Backend — RAT Detection Lab (FastAPI)

Defensive, simulation-only C2 **simulation** server. Accepts non-executable
JSON payloads, validates them through a fail-closed dispatcher, and raises
Security Engine detection events. Bound to localhost / the private lab
network by default.

## Layout
```
app/
  config.py            # env-driven settings (LAB_* vars)
  database.py          # SQLAlchemy engine/session
  main.py              # FastAPI app, security headers, CORS, size guard
  state.py             # process-wide dispatcher + collaborators
  schemas/payload.py   # the signed JSON envelope (data, never code)
  security/
    commands.py        # ALLOWED + BLOCKED command lists
    signing.py         # HMAC-SHA256 sign/verify, per-device secret registry
    replay.py          # freshness window + single-use nonce cache
    engine.py          # RULE-001..008 detection rules
    ratelimit.py       # fixed-window rate limiter
    handlers.py        # benign command handlers (static dispatch, no reflection)
    dispatcher.py      # the 7-stage pipeline
  models/              # 7 SQLAlchemy tables (UUID PKs, UTC timestamps)
  api/routes.py        # REST endpoints
  websocket/lab.py     # /ws/lab
alembic/               # migrations (initial schema generated)
tests/                 # pytest suite (mandatory payload cases + API + engine)
```

## Run locally
```bash
pip install -r requirements-dev.txt
cp .env.example .env
uvicorn app.main:app --reload           # http://127.0.0.1:8000
pytest                                   # 24 tests
ruff check .
```

## Pipeline
`Payload → Schema → Auth (device + signature) → Allowlist → Permission → Handler → Response`.
Any failure stops the pipeline, records a security event, and returns a typed
rejection. There is **no** arbitrary/dynamic/reflection execution and **no**
shell/`Runtime.exec` anywhere in this path.

See `../docs/payload-protocol.md` and `../docs/security.md`.

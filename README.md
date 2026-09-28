# Android RAT Detection Lab

> **Educational · defensive · simulation-only.** A lab for understanding,
> analyzing, and detecting the *architecture* of Android RATs — without
> building operational malware.

Sensitive capabilities exist only as clearly-labelled **simulators**. Payloads
are **non-executable JSON** validated by a strict allowlist. All communication
is confined to **localhost / a private lab network**. Device identifiers are
**synthetic UUIDs** — never IMEI/IMSI/phone/personal data. The project never
implements real keylogging, credential/SMS/cookie theft, secret capture,
shell/command execution, root/privilege escalation, exploits, evasion, hidden
persistence, injection, silent install, public C2, or control of third-party
devices.

## Structure
| Path | What |
|---|---|
| `backend/` | FastAPI C2 **simulation** server, payload validation, Security Engine ✅ foundation built |
| `dashboard/` | React + TypeScript observation console (planned) |
| `android-client/` | Kotlin + Compose lab client, simulators only (planned) |
| `docs/` | Architecture, payload protocol, detection rules, threat model, MITRE mapping, malware-analysis, telemetry |
| `tests/` | Cross-service integration tests (planned); unit tests live per service |
| `docker/`, `docker-compose.yml` | Local stack on an internal lab-network, loopback ports only |
| `.github/workflows/` | CI: lint, test, security scan |

## Quick start (backend)
```bash
cd backend
pip install -r requirements-dev.txt
uvicorn app.main:app --reload      # http://127.0.0.1:8000/health
pytest                             # 24 passing
```

## Learning path
Android security · APK structure · Android services & AccessibilityService ·
client-server & C2 concepts · payload design & validation · WebSocket &
network security · malware analysis & reverse engineering · threat modeling ·
MITRE ATT&CK · detection engineering · secure coding.

See [`docs/architecture.md`](docs/architecture.md) for the full design.

# Android RAT Detection Lab — Architecture Foundation

> **Defensive, simulation-only, educational.** No operational malware is built.
> Sensitive capabilities are labelled simulators, payloads are non-executable JSON,
> and all traffic is confined to localhost / a private lab network.

## Purpose
Reproduce the *conceptual architecture* of an Android RAT so students can study
command-and-control, payload design & validation, WebSockets, telemetry, threat
modeling, and detection engineering — **without** developing offensive capability.

## Stack
| Layer | Technology |
|---|---|
| Dashboard | React + TypeScript, Vite, Tailwind, TanStack Query, Recharts |
| Backend (C2 sim) | FastAPI, Pydantic, SQLAlchemy, Alembic, WebSocket |
| Database | PostgreSQL |
| Android lab client | Kotlin, Jetpack Compose (Material 3), MVVM + Clean Arch, Hilt, Room, Coroutines/Flow, OkHttp WS, Kotlin Serialization |
| Containerization | Docker (lab-network, no public exposure) |
| CI | GitHub Actions (lint, test, build, security_scan, dependency_check) |

## Component flow
Web Dashboard  ──HTTPS/WSS──►  Local C2 Server  ──WebSocket──►  Android Lab Client
The client emits Telemetry, Payloads, and Security Events back up the channel.

## Four planes
- **Control Plane** — command dispatch, allowlist enforcement, request/response correlation via `requestId`.
- **Data Plane** — device registry, event/payload persistence, VirtualLabFileSystem operations.
- **Telemetry Plane** — heartbeat, connection state, synthetic device metrics (no personal data).
- **Security Plane** — payload validation, signature checks, replay defense, Security Engine rules.

## Network posture
Default exposure = localhost / private network only. HTTPS + WSS, CORS, CSP, security
headers, rate limiting, request-size limits, input/message validation. No public C2,
no control of third-party devices.

## Sensitive capability → labelled simulator
| Real capability | Lab replacement | Behavior |
|---|---|---|
| camera | CameraModuleSimulator | AVAILABLE/SIMULATED/DISABLED states, no hardware |
| microphone | MicrophoneModuleSimulator | same state machine, no audio source |
| screen capture | ScreenMonitoringSimulator | placeholder card, no real capture |
| file access | VirtualLabFileSystem | list/create/read/delete in `/lab-data/` only |
| command exec | AllowlistedLabCommands | 9 benign commands, no Runtime.exec / shell |
| accessibility | LabAccessibilityService | reports own state only, reads no other apps |
| C2 | LocalC2Simulation | localhost/private-network only |

See also: `payload-protocol.md`, `security.md`, `threat-model.md`, `mitre-mapping.md`.

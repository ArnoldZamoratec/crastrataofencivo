# Security Engine — Detection Rules

The Security Engine watches every payload and connection and raises a typed
security event when a rule fires. Severity ladder: INFO · LOW · MEDIUM · HIGH · CRITICAL.

| Rule | Detection | Fires when | Severity |
|---|---|---|---|
| RULE-001 | Unknown command | `command` outside allowlist reaches dispatcher | HIGH |
| RULE-002 | Invalid signature | Recomputed HMAC ≠ envelope signature | CRITICAL |
| RULE-003 | Expired payload | Timestamp outside freshness window | MEDIUM |
| RULE-004 | Replay detected | Nonce or requestId seen a second time | HIGH |
| RULE-005 | Unauthorized device | Unregistered `deviceId` attempts a command | CRITICAL |
| RULE-006 | Unexpected permission | Client reports permission outside declared set | MEDIUM |
| RULE-007 | Unauthorized connection | WebSocket from outside allowed lab scope | HIGH |
| RULE-008 | Oversized payload | Payload exceeds configured size limit | MEDIUM |

## Structured logging
Every rule emits JSON: `timestamp · level · service · event · deviceId · requestId`.
Never logged: passwords, tokens, secrets, personal information (none exists in the system).

## Authentication
JWT, API Key, Device Registration, Token Expiration, Rate Limiting.
Secrets in `.env`; no hardcoded secrets.

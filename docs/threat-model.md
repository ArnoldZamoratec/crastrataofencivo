# Threat Model — STRIDE

The system to defend is the lab itself. Each STRIDE category maps to a surface,
a mitigation in the design, and the detection that catches it.

| STRIDE | Threat on this lab | Mitigation | Detection |
|---|---|---|---|
| Spoofing | Forged deviceId / impersonated client | Device registration, per-device HMAC key, JWT/API-key | RULE-002, RULE-005 |
| Tampering | Payload modified in transit | integrityHash + signature over canonical form; WSS | RULE-002 |
| Repudiation | Actor denies sending a command | requestId correlation, append-only audit log | event log |
| Information Disclosure | Leak of secrets / personal data | No personal data; secrets in .env; never-log list | log review |
| Denial of Service | Payload flooding / oversized messages | Rate limiting, request-size limit, bounded nonce cache | RULE-008 |
| Elevation of Privilege | Run a non-allowlisted command | Strict allowlist, no reflection/dynamic exec, scope check | RULE-001, RULE-006 |

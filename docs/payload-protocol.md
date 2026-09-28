# Payload Protocol — Non-Executable JSON

A payload is a **signed JSON envelope: data, never code.** No eval, no reflection-based
dispatch, no dynamic class loading. A `command` is a string matched against a fixed
allowlist and routed to a hand-written handler.

## Envelope fields
| Field | Meaning |
|---|---|
| `version` | Protocol version (e.g. "1.0"); mismatch rejected early |
| `type` | LAB_COMMAND / HEARTBEAT / RESPONSE / SECURITY_EVENT |
| `requestId` | Correlation id (REQ-0001); also replay tracking |
| `deviceId` | Synthetic lab id `LAB-ANDROID-XXXXXXXX` (never IMEI/IMSI/phone) |
| `command` | Allowlisted string; else dropped + RULE-001 |
| `parameters` | Typed, schema-validated, bounded object |
| `timestamp` | ISO-8601 UTC; expiration + replay window |
| `nonce` | Single-use random; repeat = replay (RULE-004) |
| `signature` | HMAC-SHA256 over canonical envelope, per-device `.env` secret |
| `integrityHash` | SHA-256 of body, checked before signature |

## Example
```json
{
  "version": "1.0",
  "type": "LAB_COMMAND",
  "requestId": "REQ-0001",
  "deviceId": "LAB-ANDROID-9F3A21C8",
  "command": "GET_DEVICE_INFO",
  "parameters": {},
  "timestamp": "2026-09-28T16:00:00Z",
  "nonce": "b7d1e0c4-2f88-4a11-9c2e-1a5f0e3b8d64",
  "signature": "hmac-sha256:5e884898da280471...",
  "integrityHash": "sha256:2c26b46b68ffc68ff9..."
}
```

## Dispatcher pipeline (fail-closed)
Payload → Schema Validation → Authentication (sig + device) → Command Allowlist →
Permission Check → Command Handler → Response. A failure at any stage stops the
pipeline, records a security event, and returns a typed rejection.

Requirements: no arbitrary command execution, no reflection-based execution,
no dynamic code execution, strict allowlist.

## Signing & replay
- **HMAC-SHA256** with per-device secret from `.env` (never hardcoded/logged); asymmetric signature is a drop-in later.
- **Replay defense**: freshness window on `timestamp` (RULE-003), single-use `nonce` (RULE-004), `requestId` dedupe. Nonce cache is bounded + time-evicted.

## Rejected conditions
invalid_signature · expired_payload · duplicate_nonce · invalid_schema ·
unknown_command · unauthorized_device · oversized_payload

## Allowed commands
PING · GET_DEVICE_INFO · GET_APP_INFO · GET_BATTERY_INFO · GET_NETWORK_STATUS ·
GET_LAB_EVENTS · SHOW_NOTIFICATION · DISPLAY_MESSAGE · SIMULATE_SECURITY_EVENT

## Blocked commands (never implemented — studied as detection targets only)
EXEC_SHELL · DOWNLOAD_EXECUTABLE · UPLOAD_EXECUTABLE · KEYLOG · STEAL_PASSWORDS ·
CAPTURE_CAMERA · CAPTURE_MIC · STEAL_SMS · STEAL_COOKIES · ROOT · INJECT_PROCESS

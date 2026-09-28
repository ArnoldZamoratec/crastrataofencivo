# Tests

Service-level test suites live next to their code:

- **Backend** — `backend/tests/` (pytest). Covers the mandatory payload cases:
  valid, invalid JSON, invalid signature, expired, replay, unknown command,
  unauthorized device, oversized, rate limit, disconnected device, plus the
  Security Engine and the REST/WebSocket surface.

This top-level folder is reserved for future cross-service integration tests.

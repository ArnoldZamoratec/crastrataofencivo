# Telemetry & Device Identity

## Device identity
- Format: `LAB-ANDROID-XXXXXXXX`, UUID-derived.
- Storage: Android Keystore or encrypted local storage.
- **Forbidden by design**: IMEI, IMSI, phone number, any personal identifier.

## Allowed telemetry fields (synthetic)
deviceId · androidVersion · appVersion · battery · network · timestamp · environment
`personal_data = false`. battery/network are simulated values, not sensor reads.

## Heartbeat
Configurable interval; timeout, exponential backoff, connection-state tracking,
offline detection. Message: `{ type: "heartbeat", deviceId, timestamp, status }`.

## Data model (PostgreSQL)
Tables: devices · events · commands · payloads · security_events · connections · permissions.
UUID PKs, UTC timestamps, indexes, foreign keys, constraints.

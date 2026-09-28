# MITRE ATT&CK Mapping (detection & mitigation study)

Technique IDs from ATT&CK for Mobile, used purely to organize detection/mitigation
study. There is **no offensive implementation** behind any row; the simulation column
is always a benign stand-in.

| Technique | Lab simulation | Detection | Mitigation |
|---|---|---|---|
| T1437 App-layer C2 | WebSocket to local C2 sim with signed JSON envelopes | Connection-scope rule; unexpected-endpoint alerts | Localhost binding, WSS, allowlisted peers (RULE-007) |
| T1071 Web protocol C2 | Heartbeat + command traffic over one WS channel | Beacon-interval / volume analysis in Network Monitor | Rate limiting, size limits |
| T1636 Protected user data | VirtualLabFileSystem holds only synthetic /lab-data/ | Access confined to virtual FS; no real URIs | No real storage permission |
| T1517 Access notifications | SHOW_NOTIFICATION renders lab-only notifications | Command allowlist audit | On-device, non-exfiltrating handler |
| T1626 Abuse elevation | LabAccessibilityService reports own state only | Permission-scope rule (RULE-006) | Reads nothing outside the lab app |
| T1407 Download new code | Blocked command, detection target only | Unknown-command rule (RULE-001) | No dynamic code path exists |

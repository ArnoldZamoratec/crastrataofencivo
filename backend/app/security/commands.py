"""Command allowlist and the explicitly blocked list.

The dispatcher can only ever route to a command in ``ALLOWED_COMMANDS``. The
``BLOCKED_COMMANDS`` set is documentation and a detection target: these are
capabilities the lab studies but never implements. There is no code path that
executes anything outside the allowlist, and no dynamic/reflection dispatch.
"""
from __future__ import annotations

# Benign, read-or-display commands the lab client understands.
ALLOWED_COMMANDS: frozenset[str] = frozenset(
    {
        "PING",
        "GET_DEVICE_INFO",
        "GET_APP_INFO",
        "GET_BATTERY_INFO",
        "GET_NETWORK_STATUS",
        "GET_LAB_EVENTS",
        "SHOW_NOTIFICATION",
        "DISPLAY_MESSAGE",
        "SIMULATE_SECURITY_EVENT",
    }
)

# Offensive capabilities that are NEVER implemented. Present only so the
# Security Engine can recognise and flag them as detection targets.
BLOCKED_COMMANDS: frozenset[str] = frozenset(
    {
        "EXEC_SHELL",
        "DOWNLOAD_EXECUTABLE",
        "UPLOAD_EXECUTABLE",
        "KEYLOG",
        "STEAL_PASSWORDS",
        "CAPTURE_CAMERA",
        "CAPTURE_MIC",
        "STEAL_SMS",
        "STEAL_COOKIES",
        "ROOT",
        "INJECT_PROCESS",
    }
)


def is_allowed(command: str) -> bool:
    return command in ALLOWED_COMMANDS


def is_explicitly_blocked(command: str) -> bool:
    return command in BLOCKED_COMMANDS

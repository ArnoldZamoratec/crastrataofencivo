"""Command handlers — benign, hand-written functions only.

Every handler returns synthetic data. None touches real hardware, real user
storage, or executes anything. There is deliberately no generic/reflection
dispatch: handlers are looked up in a static dict keyed by allowlisted name.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

HandlerResult = dict[str, Any]
Handler = Callable[[str, dict[str, Any]], HandlerResult]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _ping(device_id: str, params: dict[str, Any]) -> HandlerResult:
    return {"pong": True, "serverTime": _now()}


def _device_info(device_id: str, params: dict[str, Any]) -> HandlerResult:
    # Synthetic specs only. No real device fingerprinting.
    return {
        "deviceId": device_id,
        "model": "LabPhone Emulator",
        "androidVersion": "14",
        "simulated": True,
    }


def _app_info(device_id: str, params: dict[str, Any]) -> HandlerResult:
    return {"appVersion": "0.1.0", "package": "org.lab.ratdetection", "simulated": True}


def _battery_info(device_id: str, params: dict[str, Any]) -> HandlerResult:
    # Simulated value, not a sensor read.
    return {"level": 87, "charging": False, "simulated": True}


def _network_status(device_id: str, params: dict[str, Any]) -> HandlerResult:
    return {"state": "connected", "type": "wifi", "scope": "lab-network", "simulated": True}


def _lab_events(device_id: str, params: dict[str, Any]) -> HandlerResult:
    return {"events": [], "note": "Lab event log is served from the events repository."}


def _show_notification(device_id: str, params: dict[str, Any]) -> HandlerResult:
    title = str(params.get("title", "Lab"))[:120]
    body = str(params.get("body", ""))[:280]
    # On-device only; does not exfiltrate anything.
    return {"displayed": True, "title": title, "body": body}


def _display_message(device_id: str, params: dict[str, Any]) -> HandlerResult:
    text = str(params.get("text", ""))[:280]
    return {"displayed": True, "text": text}


def _simulate_security_event(device_id: str, params: dict[str, Any]) -> HandlerResult:
    # Training aid: lets students generate a benign, clearly-labelled event.
    kind = str(params.get("kind", "GENERIC"))[:64]
    return {"simulatedSecurityEvent": kind, "training": True}


HANDLERS: dict[str, Handler] = {
    "PING": _ping,
    "GET_DEVICE_INFO": _device_info,
    "GET_APP_INFO": _app_info,
    "GET_BATTERY_INFO": _battery_info,
    "GET_NETWORK_STATUS": _network_status,
    "GET_LAB_EVENTS": _lab_events,
    "SHOW_NOTIFICATION": _show_notification,
    "DISPLAY_MESSAGE": _display_message,
    "SIMULATE_SECURITY_EVENT": _simulate_security_event,
}

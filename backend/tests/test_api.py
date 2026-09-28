"""Integration tests over the FastAPI app (REST + WebSocket)."""
from __future__ import annotations

import os
import tempfile

import pytest

# Use an isolated SQLite file for the app under test.
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["LAB_DATABASE_URL"] = f"sqlite:///{_tmp.name}"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.state import lab_state  # noqa: E402

from .conftest import build_payload  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:  # triggers lifespan: init_db + seed demo device
        yield c


def _signed_demo_payload_json(command="PING"):
    device_id, secret = "LAB-ANDROID-DEMO0001", lab_state.settings.hmac_secret
    env = build_payload(device_id=device_id, secret=secret, command=command)
    return env.model_dump_json(by_alias=True)


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_post_command_valid(client):
    body = _signed_demo_payload_json("PING")
    r = client.post("/commands", content=body, headers={"content-type": "application/json"})
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ACCEPTED"
    assert data["result"]["pong"] is True


def test_post_command_blocked(client):
    body = _signed_demo_payload_json("KEYLOG")
    r = client.post("/commands", content=body, headers={"content-type": "application/json"})
    assert r.status_code == 200
    assert r.json()["status"] == "REJECTED"
    assert r.json()["ruleId"] == "RULE-001"


def test_security_events_listed(client):
    # The blocked command above should have produced a security event.
    r = client.get("/security/events")
    assert r.status_code == 200
    rule_ids = {e["ruleId"] for e in r.json()}
    assert "RULE-001" in rule_ids


def test_websocket_roundtrip(client):
    with client.websocket_connect("/ws/lab") as ws:
        ws.send_text(_signed_demo_payload_json("GET_DEVICE_INFO"))
        reply = ws.receive_json()
        assert reply["status"] == "ACCEPTED"
        assert reply["result"]["simulated"] is True


def test_websocket_heartbeat(client):
    with client.websocket_connect("/ws/lab") as ws:
        ws.send_text('{"type":"heartbeat","deviceId":"LAB-ANDROID-DEMO0001","status":"online"}')
        reply = ws.receive_json()
        assert reply["type"] == "heartbeat_ack"

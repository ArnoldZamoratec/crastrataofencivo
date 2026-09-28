"""REST endpoints (observation surface).

GET /health, GET /devices, GET /devices/{id}, GET /events, GET /commands,
POST /commands, GET /security/events. All bound to the lab network only.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Command, Device, Event, SecurityEventRow
from ..schemas.payload import PayloadEnvelope
from ..state import lab_state

router = APIRouter()


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "rat-detection-lab", "mode": "defensive-simulation"}


@router.get("/devices")
def list_devices(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(select(Device).order_by(Device.created_at.desc())).all()
    return [
        {
            "id": d.id,
            "deviceId": d.device_id,
            "status": d.status,
            "androidVersion": d.android_version,
            "appVersion": d.app_version,
            "environment": d.environment,
        }
        for d in rows
    ]


@router.get("/devices/{device_id}")
def get_device(device_id: str, db: Session = Depends(get_db)) -> dict:
    d = db.scalar(select(Device).where(Device.device_id == device_id))
    if d is None:
        raise HTTPException(status_code=404, detail="device not found")
    return {
        "id": d.id,
        "deviceId": d.device_id,
        "status": d.status,
        "androidVersion": d.android_version,
        "appVersion": d.app_version,
        "environment": d.environment,
    }


@router.get("/events")
def list_events(limit: int = 100, db: Session = Depends(get_db)) -> list[dict]:
    limit = max(1, min(limit, 500))
    rows = db.scalars(
        select(Event).order_by(Event.created_at.desc()).limit(limit)
    ).all()
    return [
        {"id": e.id, "deviceId": e.device_id, "kind": e.kind, "detail": e.detail}
        for e in rows
    ]


@router.get("/commands")
def list_commands(limit: int = 100, db: Session = Depends(get_db)) -> list[dict]:
    limit = max(1, min(limit, 500))
    rows = db.scalars(
        select(Command).order_by(Command.created_at.desc()).limit(limit)
    ).all()
    return [
        {
            "id": c.id,
            "requestId": c.request_id,
            "deviceId": c.device_id,
            "command": c.command,
            "status": c.status,
            "ruleId": c.rule_id,
        }
        for c in rows
    ]


@router.post("/commands")
def submit_command(envelope: PayloadEnvelope, db: Session = Depends(get_db)) -> dict:
    """Run a payload through the full dispatcher pipeline and persist the outcome."""
    result = lab_state.dispatcher.dispatch(envelope)
    db.add(
        Command(
            request_id=result.request_id or "",
            device_id=result.device_id or "",
            command=envelope.command,
            status=result.status.value,
            rule_id=result.rule_id,
        )
    )
    db.commit()
    return {
        "status": result.status.value,
        "requestId": result.request_id,
        "deviceId": result.device_id,
        "ruleId": result.rule_id,
        "reason": result.reason,
        "result": result.result,
    }


@router.get("/security/events")
def list_security_events(limit: int = 100, db: Session = Depends(get_db)) -> list[dict]:
    limit = max(1, min(limit, 500))
    rows = db.scalars(
        select(SecurityEventRow).order_by(SecurityEventRow.created_at.desc()).limit(limit)
    ).all()
    return [
        {
            "id": r.id,
            "ruleId": r.rule_id,
            "name": r.name,
            "severity": r.severity,
            "deviceId": r.device_id,
            "requestId": r.request_id,
            "detail": r.detail,
        }
        for r in rows
    ]

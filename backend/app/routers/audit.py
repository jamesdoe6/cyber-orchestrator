"""Read and verify the immutable audit log."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditEvent
from ..security import audit as audit_mod

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def list_events(engagement_id: int | None = None, limit: int = 200, db: Session = Depends(get_db)):
    q = db.query(AuditEvent)
    if engagement_id is not None:
        q = q.filter(AuditEvent.engagement_id == engagement_id)
    rows = q.order_by(AuditEvent.id.desc()).limit(limit).all()
    return {"events": [
        {"id": r.id, "ts": r.ts, "actor": r.actor, "action": r.action,
         "engagement_id": r.engagement_id, "detail": r.detail, "entry_hash": r.entry_hash}
        for r in rows
    ]}


@router.get("/verify")
def verify(db: Session = Depends(get_db)):
    return audit_mod.verify_chain(db)

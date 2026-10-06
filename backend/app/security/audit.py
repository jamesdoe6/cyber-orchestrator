"""Append-only, hash-chained audit log.

Guarantees
----------
* Every offensive/active action is recorded *before* it runs.
* Records are chained: ``entry_hash = sha256(prev_hash || canonical(record))``.
  Deleting or editing any row breaks every subsequent hash, which
  :func:`verify_chain` detects.
* Each entry is also mirrored, one JSON line per event, to an append-only
  file on disk (``var/audit/audit.log``) as a second, out-of-database copy.

This module never updates or deletes rows. It only appends.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import settings
from ..models import AuditEvent

_AUDIT_FILE = settings.paths_audit / "audit.log"
# Serializes the read-last-hash + append within a process; the UNIQUE(prev_hash)
# constraint + retry below makes it correct across processes (gunicorn workers) too.
_CHAIN_LOCK = threading.Lock()


def _canonical(record: dict) -> str:
    """Deterministic serialization used for hashing."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _hash(prev_hash: str, record: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(record)).encode("utf-8")).hexdigest()


def _last_hash(db: Session) -> str:
    row = db.execute(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)).scalar_one_or_none()
    return row.entry_hash if row else ""


def record(
    db: Session,
    *,
    action: str,
    actor: str = "",
    engagement_id: int | None = None,
    detail: dict | None = None,
) -> AuditEvent:
    """Append one audit event and return it (committed)."""
    detail = detail or {}
    ts = datetime.now(timezone.utc)
    ts_iso = ts.isoformat()
    body = {
        "ts": ts_iso,
        "engagement_id": engagement_id,
        "actor": actor,
        "action": action,
        "detail": detail,
    }

    event = None
    for _attempt in range(12):
        with _CHAIN_LOCK:
            prev = _last_hash(db)
            entry_hash = _hash(prev, body)
            event = AuditEvent(
                ts=ts, ts_iso=ts_iso, engagement_id=engagement_id, actor=actor,
                action=action, detail=detail, prev_hash=prev, entry_hash=entry_hash,
            )
            db.add(event)
            try:
                db.commit()
                db.refresh(event)
                break
            except IntegrityError:
                # Another writer took this slot (same prev_hash): retry with a fresh tail.
                db.rollback()
                event = None
                time.sleep(0.01 * (_attempt + 1))
    if event is None:
        raise RuntimeError("audit chain contention: could not append after retries")

    # Second, out-of-band copy. Best-effort: a disk error must not stop the
    # action from being recorded in the DB, but we never swallow it silently.
    try:
        with _AUDIT_FILE.open("a", encoding="utf-8") as fh:
            fh.write(_canonical({**body, "entry_hash": entry_hash}) + "\n")
    except OSError as exc:  # pragma: no cover - disk failure path
        event_detail = {"audit_file_error": str(exc)}
        db.add(AuditEvent(
            ts=datetime.now(timezone.utc), action="audit.file_error",
            detail=event_detail, prev_hash=entry_hash,
            entry_hash=_hash(entry_hash, event_detail),
        ))
        db.commit()
    return event


def verify_chain(db: Session) -> dict:
    """Walk the whole chain and report the first break, if any."""
    prev = ""
    count = 0
    for row in db.execute(select(AuditEvent).order_by(AuditEvent.id.asc())).scalars():
        body = {
            "ts": row.ts_iso,
            "engagement_id": row.engagement_id,
            "actor": row.actor,
            "action": row.action,
            "detail": row.detail,
        }
        expected = _hash(prev, body)
        if row.prev_hash != prev or row.entry_hash != expected:
            return {"valid": False, "broken_at_id": row.id, "verified": count}
        prev = row.entry_hash
        count += 1
    return {"valid": True, "broken_at_id": None, "verified": count}

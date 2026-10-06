"""Engagement (session) and scope-authorization endpoints."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Engagement, ScopeAuthorization
from ..schemas import AuthorizationIn, AuthorizationOut, EngagementCreate, EngagementOut
from ..security import audit

router = APIRouter(prefix="/api/engagements", tags=["engagements"])


def _to_out(e: Engagement) -> dict:
    return {
        "id": e.id, "name": e.name, "mode": e.mode, "operator": e.operator,
        "created_at": e.created_at, "closed_at": e.closed_at,
        "has_authorization": e.authorization is not None and e.authorization.accepted,
    }


@router.post("", response_model=EngagementOut)
def create_engagement(body: EngagementCreate, db: Session = Depends(get_db)):
    e = Engagement(name=body.name, mode=body.mode, operator=body.operator)
    db.add(e)
    db.commit()
    db.refresh(e)
    audit.record(db, action="engagement.create", actor=body.operator, engagement_id=e.id,
                 detail={"name": e.name, "mode": e.mode.value})
    return _to_out(e)


@router.get("", response_model=list[EngagementOut])
def list_engagements(db: Session = Depends(get_db)):
    return [_to_out(e) for e in db.query(Engagement).order_by(Engagement.id.desc()).all()]


@router.get("/{eid}", response_model=EngagementOut)
def get_engagement(eid: int, db: Session = Depends(get_db)):
    e = db.get(Engagement, eid)
    if not e:
        raise HTTPException(404, "engagement not found")
    return _to_out(e)


@router.post("/{eid}/authorization", response_model=AuthorizationOut)
def set_authorization(eid: int, body: AuthorizationIn, db: Session = Depends(get_db)):
    e = db.get(Engagement, eid)
    if not e:
        raise HTTPException(404, "engagement not found")
    if body.valid_until <= body.valid_from:
        raise HTTPException(400, "valid_until must be after valid_from")

    auth = e.authorization or ScopeAuthorization(engagement_id=e.id)
    auth.authorization_ref = body.authorization_ref
    auth.authorizing_party = body.authorizing_party
    auth.targets = [t.model_dump() for t in body.targets]
    auth.valid_from = body.valid_from
    auth.valid_until = body.valid_until
    auth.notes = body.notes
    auth.accepted = body.accept
    auth.accepted_at = datetime.now(timezone.utc) if body.accept else None
    db.add(auth)
    db.commit()
    db.refresh(auth)
    audit.record(db, action="scope.declare", actor=e.operator, engagement_id=e.id,
                 detail={"authorization_ref": auth.authorization_ref,
                         "authorizing_party": auth.authorizing_party,
                         "targets": auth.targets, "accepted": auth.accepted,
                         "valid_from": auth.valid_from.isoformat(),
                         "valid_until": auth.valid_until.isoformat()})
    return auth


@router.post("/{eid}/close", response_model=EngagementOut)
def close_engagement(eid: int, db: Session = Depends(get_db)):
    e = db.get(Engagement, eid)
    if not e:
        raise HTTPException(404, "engagement not found")
    e.closed_at = datetime.now(timezone.utc)
    db.commit()
    audit.record(db, action="engagement.close", actor=e.operator, engagement_id=e.id, detail={})
    return _to_out(e)


@router.delete("/{eid}/authorization")
def delete_authorization(eid: int, db: Session = Depends(get_db)):
    """Revoke/delete the scope authorization. The audit log of what already
    ran under it is append-only and is NOT removed — only the live scope is."""
    e = db.get(Engagement, eid)
    if not e:
        raise HTTPException(404, "engagement not found")
    if e.authorization is None:
        raise HTTPException(404, "no authorization to revoke")
    ref = e.authorization.authorization_ref
    audit.record(db, action="scope.revoke", actor=e.operator, engagement_id=e.id,
                 detail={"authorization_ref": ref})
    db.delete(e.authorization)
    db.commit()
    return {"ok": True, "revoked": ref, "engagement_id": eid}


@router.delete("/{eid}")
def delete_engagement(eid: int, db: Session = Depends(get_db)):
    """Delete an engagement and its runs/findings/scope/reports. The immutable
    audit events remain (append-only); a deletion event is recorded first."""
    e = db.get(Engagement, eid)
    if not e:
        raise HTTPException(404, "engagement not found")
    name = e.name
    audit.record(db, action="engagement.delete", actor=e.operator, engagement_id=e.id,
                 detail={"name": name, "runs": len(e.runs), "findings": len(e.findings)})
    # Reports reference the engagement via FK but are not in the ORM cascade; clear them.
    from ..models import Report
    for r in db.query(Report).filter(Report.engagement_id == eid).all():
        db.delete(r)
    db.delete(e)
    db.commit()
    return {"ok": True, "deleted": name, "engagement_id": eid}

"""Update-module endpoints. Nothing applies without an explicit apply call."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import updater
from ..database import get_db
from ..security import audit

router = APIRouter(prefix="/api/updates", tags=["updates"])


@router.get("/attack/check")
def attack_check():
    res = updater.check_attack()
    return {"ok": res["ok"], "changelog": res.get("changelog"),
            "technique_count": res.get("technique_count"), "error": res.get("error")}


@router.post("/attack/apply")
def attack_apply(db: Session = Depends(get_db)):
    res = updater.check_attack()
    applied = updater.apply_attack(res)
    if applied.get("ok"):
        audit.record(db, action="update.attack.apply", actor="system",
                     detail={"technique_count": applied["technique_count"]})
    return applied


@router.get("/cves/check")
def cve_check(days: int = 7, limit: int = 20):
    return updater.check_recent_cves(days=days, limit=limit)

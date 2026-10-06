"""Launch plugin runs and read their results."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import orchestrator
from ..database import get_db
from ..models import Engagement, Run
from ..plugins import registry
from ..schemas import RunCreate, RunOut

router = APIRouter(prefix="/api/engagements/{eid}/runs", tags=["runs"])


@router.post("", response_model=RunOut)
def launch_run(eid: int, body: RunCreate, db: Session = Depends(get_db)):
    e = db.get(Engagement, eid)
    if not e:
        raise HTTPException(404, "engagement not found")
    plugin = registry.get(body.plugin)
    if not plugin:
        raise HTTPException(404, f"plugin '{body.plugin}' not found")
    if plugin.meta.mode != e.mode:
        raise HTTPException(400, f"plugin is for {plugin.meta.mode.value}, engagement is {e.mode.value}")
    try:
        run = orchestrator.launch(db, engagement=e, plugin=plugin, params=body.params, actor=e.operator)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return run


@router.get("", response_model=list[RunOut])
def list_runs(eid: int, db: Session = Depends(get_db)):
    return db.query(Run).filter(Run.engagement_id == eid).order_by(Run.id.desc()).all()


@router.get("/{run_id}", response_model=RunOut)
def get_run(eid: int, run_id: int, db: Session = Depends(get_db)):
    run = db.get(Run, run_id)
    if not run or run.engagement_id != eid:
        raise HTTPException(404, "run not found")
    return run

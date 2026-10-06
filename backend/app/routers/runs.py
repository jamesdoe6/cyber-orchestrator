"""Launch plugin runs (background by default) and read their results."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from .. import orchestrator, runner_service
from ..database import get_db
from ..models import Engagement, Run, RunStatus
from ..plugins import registry
from ..schemas import RunCreate, RunOut

router = APIRouter(prefix="/api/engagements/{eid}/runs", tags=["runs"])


@router.post("", response_model=RunOut)
def launch_run(eid: int, body: RunCreate, wait: bool = False, db: Session = Depends(get_db)):
    """Queue a run. Returns immediately with status 'pending' (watch the WebSocket
    at /ws/engagements/{eid} for live progress). Pass ?wait=true to block until the
    run reaches a terminal state and return the full result (CLI/testing)."""
    e = db.get(Engagement, eid)
    if not e:
        raise HTTPException(404, "engagement not found")
    plugin = registry.get(body.plugin)
    if not plugin:
        raise HTTPException(404, f"plugin '{body.plugin}' not found")
    if plugin.meta.mode != e.mode:
        raise HTTPException(400, f"plugin is for {plugin.meta.mode.value}, engagement is {e.mode.value}")
    try:
        if wait:
            return orchestrator.launch(db, engagement=e, plugin=plugin, params=body.params, actor=e.operator)
        run = orchestrator.prepare(db, engagement=e, plugin=plugin, params=body.params, actor=e.operator)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if run.status == RunStatus.pending:
        runner_service.submit(orchestrator.execute_run, run.id, e.operator)
    return run


@router.get("", response_model=list[RunOut])
def list_runs(eid: int, db: Session = Depends(get_db)):
    return (db.query(Run).options(selectinload(Run.findings))
            .filter(Run.engagement_id == eid).order_by(Run.id.desc()).all())


@router.get("/{run_id}", response_model=RunOut)
def get_run(eid: int, run_id: int, db: Session = Depends(get_db)):
    run = db.get(Run, run_id)
    if not run or run.engagement_id != eid:
        raise HTTPException(404, "run not found")
    return run

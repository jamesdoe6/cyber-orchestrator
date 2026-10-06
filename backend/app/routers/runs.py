"""Launch plugin runs (background by default) and read their results."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from datetime import datetime, timezone

from .. import orchestrator, run_control, runner_service
from ..database import get_db
from ..events import bus
from ..models import Engagement, Run, RunStatus
from ..security import audit
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


@router.post("/{run_id}/cancel")
def cancel_run(eid: int, run_id: int, db: Session = Depends(get_db)):
    """Stop a running (or queued) scan. Kills the subprocess and marks it cancelled."""
    run = db.get(Run, run_id)
    if not run or run.engagement_id != eid:
        raise HTTPException(404, "run not found")
    if run.status in (RunStatus.completed, RunStatus.failed, RunStatus.blocked, RunStatus.cancelled):
        return {"ok": False, "status": run.status.value, "message": "run already finished"}

    # Signal cancellation (kills the live process if running).
    run_control.cancel(run_id)
    # Atomically cancel it if still queued; the worker's guard then skips it.
    updated = (db.query(Run)
               .filter(Run.id == run_id, Run.status == RunStatus.pending)
               .update({Run.status: RunStatus.cancelled, Run.error: "cancelled by operator",
                        Run.finished_at: datetime.now(timezone.utc)}, synchronize_session=False))
    db.commit()
    if updated:
        audit.record(db, action="run.cancel", actor=run.engagement.operator, engagement_id=eid,
                     detail={"run_id": run_id, "phase": "queued"})
        bus.publish(eid, {"type": "done", "run_id": run_id, "plugin": run.plugin,
                          "status": "cancelled", "error": "cancelled by operator", "findings": 0})
        return {"ok": True, "status": "cancelled"}
    # It was running: the kill signal will stop it; the worker finalizes it.
    audit.record(db, action="run.cancel.request", actor=run.engagement.operator, engagement_id=eid,
                 detail={"run_id": run_id, "phase": "running"})
    return {"ok": True, "status": "cancelling"}


@router.post("/cancel-all")
def cancel_all(eid: int, db: Session = Depends(get_db)):
    """Stop every running/queued scan of this engagement (global Stop)."""
    e = db.get(Engagement, eid)
    if not e:
        raise HTTPException(404, "engagement not found")
    active = (db.query(Run)
              .filter(Run.engagement_id == eid,
                      Run.status.in_([RunStatus.pending, RunStatus.running])).all())
    for run in active:
        run_control.cancel(run.id)  # kills running subprocesses
    queued = (db.query(Run)
              .filter(Run.engagement_id == eid, Run.status == RunStatus.pending)
              .update({Run.status: RunStatus.cancelled, Run.error: "cancelled by operator (stop all)",
                       Run.finished_at: datetime.now(timezone.utc)}, synchronize_session=False))
    db.commit()
    if active:
        audit.record(db, action="run.cancel.all", actor=e.operator, engagement_id=eid,
                     detail={"count": len(active)})
    for run in active:
        if run.status == RunStatus.pending:  # was queued -> now cancelled
            bus.publish(eid, {"type": "done", "run_id": run.id, "plugin": run.plugin,
                              "status": "cancelled", "error": "cancelled by operator", "findings": 0})
    return {"ok": True, "requested": len(active), "cancelled_queued": queued}


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

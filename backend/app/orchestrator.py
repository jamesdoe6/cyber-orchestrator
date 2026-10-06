"""Run orchestration — the single path every tool execution takes.

Flow:
    prepare()  : validate -> SCOPE GUARD -> AUDIT(request/blocked)  [synchronous]
    execute_run(): AUDIT(launch) -> execute (stream/python/sim) -> parse
                   -> findings -> persist -> AUDIT(complete/failed)  [background]

Both publish live events to the :mod:`app.events` bus for WebSocket subscribers.
No plugin is ever executed except through here, so scope enforcement and
auditing cannot be bypassed.
"""
from __future__ import annotations

import subprocess
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .database import SessionLocal
from .events import bus
from .models import Engagement, Finding, Run, RunStatus
from .plugins import registry
from .plugins.base import BasePlugin, ExecResult, ToolRunner
from .security import audit, scope

_MAX_STR = 2048
_MAX_TEXTAREA = 8192
_MAX_RAW = 500_000
_MAX_STREAM_LINES = 1000


def _validate_params(plugin: BasePlugin, params: dict) -> dict:
    cleaned = dict(params)
    for p in plugin.meta.params:
        if p.name not in cleaned or cleaned[p.name] in (None, ""):
            if p.required and p.default is None:
                raise ValueError(f"missing required parameter: {p.name}")
            cleaned[p.name] = p.default
        if p.type == "int" and cleaned.get(p.name) not in (None, ""):
            cleaned[p.name] = int(cleaned[p.name])
        if p.type == "bool":
            cleaned[p.name] = bool(cleaned.get(p.name))
        if p.type == "choice" and cleaned.get(p.name) and cleaned[p.name] not in p.choices:
            raise ValueError(f"invalid choice for {p.name}: {cleaned[p.name]}")
    _harden_params(plugin, cleaned)
    return cleaned


def _harden_params(plugin: BasePlugin, cleaned: dict) -> None:
    for p in plugin.meta.params:
        v = cleaned.get(p.name)
        if not isinstance(v, str) or not v:
            continue
        allowed_ctrl = {"\n", "\t", "\r"} if p.type == "textarea" else set()
        if any((ord(ch) < 32 and ch not in allowed_ctrl) or ord(ch) == 127 for ch in v):
            raise ValueError(f"{p.name}: control characters are not allowed")
        limit = _MAX_TEXTAREA if p.type == "textarea" else _MAX_STR
        if len(v) > limit:
            raise ValueError(f"{p.name}: value too long (max {limit})")
        if plugin.meta.binary and p.type == "string" and v.lstrip().startswith("-"):
            raise ValueError(f"{p.name}: value may not start with '-' (argument-injection guard)")


def prepare(db: Session, *, engagement: Engagement, plugin: BasePlugin,
            params: dict, actor: str) -> Run:
    """Validate, scope-check and queue a run. Returns it (status pending|blocked)."""
    params = _validate_params(plugin, params)
    target = str(params.get("target", "") or "")

    run = Run(engagement_id=engagement.id, plugin=plugin.meta.slug, target=target,
              params=params, attack_techniques=list(plugin.meta.attack_techniques),
              status=RunStatus.pending)
    db.add(run)
    db.commit()
    db.refresh(run)

    audit.record(db, action="run.request", actor=actor, engagement_id=engagement.id,
                 detail={"run_id": run.id, "plugin": plugin.meta.slug, "target": target,
                         "privilege": plugin.meta.privilege})

    decision = scope.check(engagement, privilege=plugin.meta.privilege, target=target)
    if not decision.allowed:
        run.status = RunStatus.blocked
        run.error = decision.reason
        db.commit()
        audit.record(db, action="run.blocked", actor=actor, engagement_id=engagement.id,
                     detail={"run_id": run.id, "reason": decision.reason, "target": target})
        bus.publish(engagement.id, {"type": "done", "run_id": run.id, "plugin": plugin.meta.slug,
                                    "status": "blocked", "error": decision.reason, "findings": 0})
    return run


def execute_run(run_id: int, actor: str, timeout: int = 1800) -> None:
    """Execute a prepared run in the background, streaming live events."""
    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if run is None or run.status != RunStatus.pending:
            return
        plugin = registry.get(run.plugin)
        eid = run.engagement_id
        params = dict(run.params or {})

        argv = plugin.build_argv(params) if plugin.meta.binary else None
        run.command = " ".join(argv) if argv else plugin.meta.slug
        run.status = RunStatus.running
        run.started_at = datetime.now(timezone.utc)
        db.commit()
        bus.publish(eid, {"type": "status", "run_id": run_id, "plugin": run.plugin,
                          "target": run.target, "status": "running", "command": run.command})
        audit.record(db, action="run.launch", actor=actor, engagement_id=eid,
                     detail={"run_id": run_id, "command": run.command})

        runner = ToolRunner(timeout=timeout)
        published = 0

        def on_line(line: str) -> None:
            nonlocal published
            if published < _MAX_STREAM_LINES:
                bus.publish(eid, {"type": "line", "run_id": run_id, "line": line})
                published += 1
            elif published == _MAX_STREAM_LINES:
                bus.publish(eid, {"type": "line", "run_id": run_id,
                                  "line": "[... output truncated in live view ...]"})
                published += 1

        if plugin.meta.binary is None:
            bus.publish(eid, {"type": "line", "run_id": run_id, "line": "[running local analyzer]"})
            result = plugin.execute_python(params)
            for ln in (result.raw_output or "").splitlines()[:_MAX_STREAM_LINES]:
                bus.publish(eid, {"type": "line", "run_id": run_id, "line": ln})
        elif ToolRunner.available(plugin.meta.binary):
            result = runner.stream(argv, on_line)
        else:
            sim = plugin.simulate(params)
            for ln in sim.splitlines():
                on_line(ln)
            result = ExecResult(raw_output=sim, exit_code=0, command=run.command, simulated=True)

        parsed = plugin.parse(result.raw_output, params)
        drafts = plugin.findings(parsed, params)

        raw = result.raw_output or ""
        run.raw_output = raw if len(raw) <= _MAX_RAW else raw[:_MAX_RAW] + "\n...[truncated]"
        run.parsed = {**parsed, "_simulated": getattr(result, "simulated", False)}
        run.exit_code = result.exit_code
        run.status = RunStatus.completed
        run.finished_at = datetime.now(timezone.utc)
        for d in drafts:
            db.add(Finding(engagement_id=eid, run_id=run_id, title=d.title,
                           description=d.description, severity=d.severity, cvss=d.cvss,
                           asset=d.asset, attack_technique=d.attack_technique,
                           remediation=d.remediation, evidence=d.evidence))
        db.commit()
        audit.record(db, action="run.complete", actor=actor, engagement_id=eid,
                     detail={"run_id": run_id, "findings": len(drafts),
                             "simulated": getattr(result, "simulated", False)})
        bus.publish(eid, {"type": "done", "run_id": run_id, "plugin": run.plugin,
                          "status": "completed", "findings": len(drafts),
                          "simulated": getattr(result, "simulated", False)})
    except (subprocess.TimeoutExpired, Exception) as exc:  # noqa: BLE001
        db.rollback()
        run = db.get(Run, run_id)
        if run is not None:
            run.status = RunStatus.failed
            run.error = f"{type(exc).__name__}: {exc}"
            run.finished_at = datetime.now(timezone.utc)
            db.commit()
            audit.record(db, action="run.failed", actor=actor, engagement_id=run.engagement_id,
                         detail={"run_id": run_id, "error": run.error})
            bus.publish(run.engagement_id, {"type": "done", "run_id": run_id, "plugin": run.plugin,
                                            "status": "failed", "error": run.error, "findings": 0})
    finally:
        db.close()


def launch(db: Session, *, engagement: Engagement, plugin: BasePlugin,
           params: dict, actor: str, timeout: int = 600) -> Run:
    """Synchronous convenience: prepare + execute inline. Used by ?wait=true and tests."""
    run = prepare(db, engagement=engagement, plugin=plugin, params=params, actor=actor)
    if run.status == RunStatus.blocked:
        return run
    execute_run(run.id, actor, timeout=timeout)
    db.expire_all()
    return db.get(Run, run.id)

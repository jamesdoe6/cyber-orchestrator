"""Run orchestration — the single path every tool execution takes.

Flow for every launch:
    validate params -> SCOPE GUARD -> AUDIT(launch) -> execute (real or simulated)
    -> parse -> derive findings -> persist -> AUDIT(complete/failed)

No plugin is ever executed except through here, so scope enforcement and
auditing cannot be bypassed.
"""
from __future__ import annotations

import subprocess
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .models import Engagement, Finding, Run, RunStatus
from .plugins.base import BasePlugin, ExecResult, ToolRunner
from .security import audit, scope


def _validate_params(plugin: BasePlugin, params: dict) -> dict:
    cleaned = dict(params)
    for p in plugin.meta.params:
        if p.name not in cleaned or cleaned[p.name] in (None, ""):
            # A parameter with a default is satisfiable even if marked required.
            if p.required and p.default is None:
                raise ValueError(f"missing required parameter: {p.name}")
            cleaned[p.name] = p.default
        if p.type == "int" and cleaned.get(p.name) not in (None, ""):
            cleaned[p.name] = int(cleaned[p.name])
        if p.type == "bool":
            cleaned[p.name] = bool(cleaned.get(p.name))
        if p.type == "choice" and cleaned.get(p.name) and cleaned[p.name] not in p.choices:
            raise ValueError(f"invalid choice for {p.name}: {cleaned[p.name]}")
    return cleaned


def launch(
    db: Session,
    *,
    engagement: Engagement,
    plugin: BasePlugin,
    params: dict,
    actor: str,
    timeout: int = 600,
) -> Run:
    params = _validate_params(plugin, params)
    target = str(params.get("target", "") or "")

    run = Run(
        engagement_id=engagement.id,
        plugin=plugin.meta.slug,
        target=target,
        params=params,
        attack_techniques=list(plugin.meta.attack_techniques),
        status=RunStatus.pending,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    audit.record(db, action="run.request", actor=actor, engagement_id=engagement.id,
                 detail={"run_id": run.id, "plugin": plugin.meta.slug, "target": target,
                         "privilege": plugin.meta.privilege})

    # --- SCOPE GUARD: the blocking control ---
    decision = scope.check(engagement, privilege=plugin.meta.privilege, target=target)
    if not decision.allowed:
        run.status = RunStatus.blocked
        run.error = decision.reason
        db.commit()
        audit.record(db, action="run.blocked", actor=actor, engagement_id=engagement.id,
                     detail={"run_id": run.id, "reason": decision.reason, "target": target})
        return run

    # Build the resolved command (for audit + report) before running.
    argv = plugin.build_argv(params) if plugin.meta.binary else None
    run.command = " ".join(argv) if argv else plugin.meta.slug
    run.status = RunStatus.running
    run.started_at = datetime.now(timezone.utc)
    db.commit()

    audit.record(db, action="run.launch", actor=actor, engagement_id=engagement.id,
                 detail={"run_id": run.id, "command": run.command,
                         "matched_scope": decision.matched})

    runner = ToolRunner(timeout=timeout)
    try:
        if plugin.meta.binary is None:
            result = plugin.execute_python(params)
        elif ToolRunner.available(plugin.meta.binary):
            result = runner.run(argv)  # type: ignore[arg-type]
        else:
            # Wrapped binary not installed on this host: produce a clearly
            # flagged simulated result so the pipeline stays exercisable.
            result = ExecResult(raw_output=plugin.simulate(params), exit_code=0,
                                command=run.command, simulated=True)
        raw = result.raw_output
        parsed = plugin.parse(raw, params)
        drafts = plugin.findings(parsed, params)

        run.raw_output = raw
        run.parsed = {**parsed, "_simulated": getattr(result, "simulated", False)}
        run.exit_code = result.exit_code
        run.status = RunStatus.completed
        run.finished_at = datetime.now(timezone.utc)

        for d in drafts:
            db.add(Finding(
                engagement_id=engagement.id, run_id=run.id, title=d.title,
                description=d.description, severity=d.severity, cvss=d.cvss,
                asset=d.asset, attack_technique=d.attack_technique,
                remediation=d.remediation, evidence=d.evidence,
            ))
        db.commit()
        audit.record(db, action="run.complete", actor=actor, engagement_id=engagement.id,
                     detail={"run_id": run.id, "findings": len(drafts),
                             "simulated": getattr(result, "simulated", False)})
    except (subprocess.TimeoutExpired, Exception) as exc:  # noqa: BLE001 - record and surface
        db.rollback()
        run = db.get(Run, run.id)
        run.status = RunStatus.failed
        run.error = f"{type(exc).__name__}: {exc}"
        run.finished_at = datetime.now(timezone.utc)
        db.commit()
        audit.record(db, action="run.failed", actor=actor, engagement_id=engagement.id,
                     detail={"run_id": run.id, "error": run.error})
    return run

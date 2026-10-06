"""Generate, list and download engagement reports."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pathlib import Path as _Path

from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Engagement, Report
from ..reporting.generator import generate_report
from ..security import audit

router = APIRouter(prefix="/api", tags=["reports"])


@router.post("/engagements/{eid}/report")
def create_report(eid: int, db: Session = Depends(get_db)):
    e = db.get(Engagement, eid)
    if not e:
        raise HTTPException(404, "engagement not found")
    report = generate_report(db, e)
    audit.record(db, action="report.generate", actor=e.operator, engagement_id=e.id,
                 detail={"report_id": report.id, "html": report.html_path, "pdf": report.pdf_path})
    return {"id": report.id, "html_path": report.html_path, "pdf_path": report.pdf_path,
            "summary": report.summary}


@router.get("/reports")
def list_reports(db: Session = Depends(get_db)):
    rows = db.query(Report).order_by(Report.id.desc()).all()
    return {"reports": [
        {"id": r.id, "engagement_id": r.engagement_id, "mode": r.mode.value,
         "created_at": r.created_at, "html_path": r.html_path, "pdf_path": r.pdf_path}
        for r in rows
    ]}


@router.get("/reports/{rid}/download")
def download_report(rid: int, fmt: str = "html", db: Session = Depends(get_db)):
    r = db.get(Report, rid)
    if not r:
        raise HTTPException(404, "report not found")
    path = r.pdf_path if fmt == "pdf" else r.html_path
    if not path:
        raise HTTPException(404, f"{fmt} not available for this report")
    # Defense-in-depth: only ever serve files from within the reports directory.
    from ..config import settings
    resolved = _Path(path).resolve()
    if not str(resolved).startswith(str(_Path(settings.paths_reports).resolve())):
        raise HTTPException(403, "path outside report store")
    if not resolved.exists():
        raise HTTPException(404, "report file missing")
    media = "application/pdf" if fmt == "pdf" else "text/html"
    return FileResponse(str(resolved), media_type=media)

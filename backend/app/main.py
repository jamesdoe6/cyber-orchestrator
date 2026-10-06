"""FastAPI application entrypoint.

Local-first and loopback-only: run with ``python -m app`` (see __main__.py) or
``uvicorn app.main:app --host 127.0.0.1 --port 8777``. The frontend single-page
UI is served at ``/``.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from .config import settings
from .database import init_db
from .plugins import registry
from .routers import audit, engagements, plugins, reports, runs, updates

@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    registry.load_all()
    yield


app = FastAPI(
    title="Cyber Orchestrator",
    version="0.1.0",
    description="Local orchestration layer for authorized pentest / OSINT / threat-defense.",
    lifespan=lifespan,
)

app.include_router(engagements.router)
app.include_router(plugins.router)
app.include_router(runs.router)
app.include_router(audit.router)
app.include_router(reports.router)
app.include_router(updates.router)

_FRONTEND = Path(__file__).resolve().parent.parent.parent / "frontend" / "index.html"


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "offensive_enabled": settings.offensive_enabled,
        "enforce_scope": settings.enforce_scope,
        "plugins": len(registry.all_plugins()),
    }


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    if _FRONTEND.exists():
        return _FRONTEND.read_text(encoding="utf-8")
    return "<h1>Cyber Orchestrator</h1><p>Frontend not found. API is at /docs.</p>"

"""FastAPI application entrypoint.

Local-first and loopback-only: run with ``python -m app`` (see __main__.py) or
``uvicorn app.main:app --host 127.0.0.1 --port 8777``. The frontend single-page
UI is served at ``/``.
"""
from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

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

app.add_middleware(GZipMiddleware, minimum_size=1024)

app.include_router(engagements.router)
app.include_router(plugins.router)
app.include_router(runs.router)
app.include_router(audit.router)
app.include_router(reports.router)
app.include_router(updates.router)


@app.middleware("http")
async def _token_guard(request: Request, call_next):
    """Optional production auth. Active only when CO_API_TOKEN is set."""
    token = settings.api_token
    path = request.url.path
    if token and path.startswith("/api/") and path != "/api/health":
        supplied = request.headers.get("X-API-Token") or request.query_params.get("token")
        if not supplied or not secrets.compare_digest(str(supplied), str(token)):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)


_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com data:; "
    "img-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = _CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp

_FRONTEND = Path(__file__).resolve().parent.parent.parent / "frontend" / "index.html"


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "offensive_enabled": settings.offensive_enabled,
        "enforce_scope": settings.enforce_scope,
        "plugins": len(registry.all_plugins()),
        "auth_required": bool(settings.api_token),
    }


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    if _FRONTEND.exists():
        return _FRONTEND.read_text(encoding="utf-8")
    return "<h1>Cyber Orchestrator</h1><p>Frontend not found. API is at /docs.</p>"

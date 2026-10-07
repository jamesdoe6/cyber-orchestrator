"""Catalog of available plugins (drives the UI menu and the wizard)."""
from __future__ import annotations

from fastapi import APIRouter

from ..mitre import enrich
from ..plugins import registry
from ..plugins.base import ToolRunner

router = APIRouter(prefix="/api/plugins", tags=["plugins"])


@router.get("")
def list_plugins(mode: str | None = None):
    out = []
    for p in registry.all_plugins():
        if mode and p.meta.mode.value != mode:
            continue
        d = p.meta.to_dict()
        d["attack_detail"] = enrich(p.meta.attack_techniques)
        d["installed"] = p.meta.binary is None or p.resolve_binary() is not None
        out.append(d)
    return {"plugins": out}


@router.get("/{slug}")
def get_plugin(slug: str):
    p = registry.get(slug)
    if not p:
        return {"error": "not_found"}
    d = p.meta.to_dict()
    d["attack_detail"] = enrich(p.meta.attack_techniques)
    d["installed"] = p.meta.binary is None or p.resolve_binary() is not None
    return d

"""Continuous-update module.

Checks external feeds and returns a *changelog* for operator review. Nothing is
applied silently: ``check_*`` fetches and reports; ``apply_attack`` writes the
refreshed ATT&CK table to ``var/attack.json`` only when explicitly called.

All outbound traffic is operator-initiated and optional; the platform works
fully offline without ever calling these.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx

from .config import settings


def check_attack() -> dict:
    """Fetch the ATT&CK Enterprise STIX bundle and summarize techniques."""
    try:
        with httpx.Client(timeout=60) as client:
            resp = client.get(settings.mitre_attack_stix_url)
            resp.raise_for_status()
            bundle = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": str(exc)}

    techniques: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked"):
            continue
        ext = next((r for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        tid = ext.get("external_id", "")
        phases = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])]
        techniques[tid] = {"name": obj.get("name", ""),
                           "tactic": ", ".join(phases).replace("-", " ").title()}
    return {"ok": True, "technique_count": len(techniques), "techniques": techniques,
            "changelog": f"ATT&CK bundle parsed: {len(techniques)} techniques available."}


def apply_attack(result: dict) -> dict:
    """Persist a successful check_attack() result to var/attack.json."""
    if not result.get("ok"):
        return {"ok": False, "error": "refusing to apply a failed/empty check"}
    path = settings.paths_data / "attack.json"
    path.write_text(json.dumps(result["techniques"], indent=0), encoding="utf-8")
    return {"ok": True, "written": str(path), "technique_count": result["technique_count"]}


def check_recent_cves(days: int = 7, limit: int = 20) -> dict:
    """List recently-published CVEs from the NVD API (operator key optional)."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": limit,
    }
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    try:
        with httpx.Client(timeout=60) as client:
            resp = client.get(settings.nvd_api_base, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        return {"ok": False, "error": str(exc)}

    items = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                score = metrics[key][0]["cvssData"]["baseScore"]
                break
        items.append({"id": cve.get("id"), "cvss": score,
                      "published": cve.get("published")})
    return {"ok": True, "count": len(items), "cves": items,
            "changelog": f"{len(items)} CVEs published in the last {days} day(s)."}

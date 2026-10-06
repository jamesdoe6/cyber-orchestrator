"""Nikto web server scan (ATTACK / Vulnerability scan, active). ATT&CK T1595.002."""
from __future__ import annotations
import json
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Nikto(BasePlugin):
    meta = PluginMeta(
        slug="nikto", name="Nikto (web server scan)", mode=Mode.attack,
        category="Scan de vulnérabilités", privilege="active", binary="nikto",
        description="Check a web server for known misconfigurations and dangerous files.",
        attack_techniques=["T1595.002"],
        params=[Param("target", "Target URL/host", "string", help="e.g. https://web.example.com (in scope).")],
        steps=[
            Step("target", "1. Target", "Web server to scan (in scope).", ["target"], "A target."),
            Step("run", "2. Scan", "Run checks and collect issues.", [], "Server findings."),
        ],
    )

    def build_argv(self, p):
        return ["nikto", "-host", p["target"], "-Format", "json", "-output", "-", "-nointeractive"]

    def simulate(self, p):
        return json.dumps({"vulnerabilities": [
            {"id": "999103", "msg": "Server leaks version via Server header", "url": "/"},
            {"id": "000577", "msg": "/admin/: Admin login page found", "url": "/admin/"},
        ]})

    def parse(self, raw, p):
        try:
            data = json.loads(raw[raw.index("{"):raw.rindex("}") + 1])
            vulns = data.get("vulnerabilities", [])
        except (ValueError, json.JSONDecodeError):
            vulns = [{"msg": l} for l in raw.splitlines() if l.strip().startswith("+")]
        return {"vulns": vulns, "count": len(vulns)}

    def findings(self, parsed, p):
        out = []
        for v in parsed["vulns"]:
            msg = v.get("msg", "")
            sev = Severity.medium if any(k in msg.lower() for k in ("admin", "backup", "config", "directory")) else Severity.low
            out.append(FindingDraft(title=msg[:120] or "Nikto finding", severity=sev,
                                    attack_technique="T1595.002", asset=p["target"] + v.get("url", ""),
                                    evidence={"id": v.get("id")}))
        return out

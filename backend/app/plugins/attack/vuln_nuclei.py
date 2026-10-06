"""Nuclei template-based scanning (ATTACK / Vulnerability scan, active). ATT&CK T1595."""
from __future__ import annotations
import json
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step

_SEV = {"info": Severity.info, "low": Severity.low, "medium": Severity.medium,
        "high": Severity.high, "critical": Severity.critical, "unknown": Severity.info}


class Nuclei(BasePlugin):
    meta = PluginMeta(
        slug="nuclei", name="Nuclei (template scan)", mode=Mode.attack,
        category="Scan de vulnérabilités", privilege="active", binary="nuclei",
        description="Scan a target URL/host against the community template library (JSONL output).",
        attack_techniques=["T1595", "T1595.002"],
        params=[
            Param("target", "Target URL/host", "string", help="e.g. https://app.example.com (in scope)."),
            Param("severity", "Min severity", "choice", required=False, default="low",
                  choices=["info", "low", "medium", "high", "critical"], help="Filter out findings below this."),
        ],
        steps=[
            Step("target", "1. Target", "URL or host to scan (must be in scope).", ["target"], "A target."),
            Step("sev", "2. Severity filter", "Minimum severity to report.", ["severity"], "A threshold."),
            Step("run", "3. Scan", "Run templates and collect matches.", [], "Template matches as findings."),
        ],
    )

    def build_argv(self, p):
        return ["nuclei", "-u", p["target"], "-severity",
                ",".join(["info", "low", "medium", "high", "critical"][
                    ["info", "low", "medium", "high", "critical"].index(p.get("severity", "low")):]),
                "-jsonl", "-silent"]

    def simulate(self, p):
        t = p.get("target", "https://app.example.com")
        return "\n".join([
            json.dumps({"template-id": "tech-detect", "info": {"name": "nginx detected", "severity": "info"}, "matched-at": t}),
            json.dumps({"template-id": "tls-version", "info": {"name": "TLS 1.0 supported", "severity": "medium"}, "matched-at": t}),
            json.dumps({"template-id": "exposed-git", "info": {"name": "Exposed .git directory", "severity": "high"}, "matched-at": t + "/.git/"}),
        ])

    def parse(self, raw, p):
        rows = []
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return {"matches": rows, "count": len(rows)}

    def findings(self, parsed, p):
        out = []
        for m in parsed["matches"]:
            info = m.get("info", {})
            out.append(FindingDraft(
                title=info.get("name", m.get("template-id", "nuclei match")),
                severity=_SEV.get((info.get("severity") or "info").lower(), Severity.info),
                attack_technique="T1595.002", asset=m.get("matched-at", p["target"]),
                description=f"Template {m.get('template-id','')} matched.",
                evidence={"template": m.get("template-id")}))
        return out

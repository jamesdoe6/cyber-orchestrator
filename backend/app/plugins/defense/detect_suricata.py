"""Suricata alert review (DEFENSE / Intrusion detection, passive).

Parses Suricata eve.json alert events. Run Suricata itself (host or container)
against a capture or live interface; this plugin ingests its eve.json.
"""
from __future__ import annotations
import json, shutil
from ...models import Mode, Severity
from ..base import BasePlugin, ExecResult, FindingDraft, Param, PluginMeta, Step

_SEV = {1: Severity.high, 2: Severity.medium, 3: Severity.low}


class Suricata(BasePlugin):
    meta = PluginMeta(
        slug="suricata_alerts", name="Suricata alerts (eve.json)", mode=Mode.defense,
        category="Détection d'intrusion / monitoring", privilege="passive", binary=None,
        description="Ingest and prioritize Suricata IDS alerts from an eve.json file.",
        attack_techniques=["T1071"],
        params=[
            Param("eve_path", "eve.json path", "string", required=False, default="",
                  help="Path to Suricata eve.json. Empty = sample data."),
            Param("min_severity", "Min severity (1=high)", "int", required=False, default=3,
                  help="Keep alerts with suricata severity <= this (1 high .. 3 low)."),
        ],
        steps=[
            Step("src", "1. Alert source", "Path to Suricata eve.json (or leave empty for sample).", ["eve_path"], "An eve.json."),
            Step("filter", "2. Filter", "Minimum severity to surface.", ["min_severity"], "A threshold."),
            Step("run", "3. Review", "Aggregate alerts by signature and source.", [], "Prioritized IDS alerts."),
        ],
    )

    _SAMPLE = "\n".join([
        json.dumps({"event_type": "alert", "src_ip": "203.0.113.9", "dest_ip": "10.0.0.5",
                    "alert": {"signature": "ET SCAN Nmap Scripting Engine", "severity": 2}}),
        json.dumps({"event_type": "alert", "src_ip": "203.0.113.9", "dest_ip": "10.0.0.5",
                    "alert": {"signature": "ET EXPLOIT Possible CVE-2021-44228 (Log4Shell)", "severity": 1}}),
    ])

    def execute_python(self, p):
        path = (p.get("eve_path") or "").strip()
        simulated = False
        if path:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    raw = fh.read()
            except OSError as exc:
                return ExecResult(f"[error] cannot read {path}: {exc}", 1, f"read {path}")
        else:
            raw, simulated = self._SAMPLE, True
        return ExecResult(raw, 0, "python:suricata_alerts", simulated=simulated)

    def parse(self, raw, p):
        thr = int(p.get("min_severity", 3) or 3)
        agg = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("event_type") != "alert":
                continue
            a = e.get("alert", {})
            if a.get("severity", 3) > thr:
                continue
            sig = a.get("signature", "unknown")
            key = (sig, e.get("src_ip", ""))
            agg.setdefault(key, {"signature": sig, "src_ip": e.get("src_ip"), "dest_ip": e.get("dest_ip"),
                                 "severity": a.get("severity", 3), "count": 0})
            agg[key]["count"] += 1
        return {"alerts": list(agg.values()), "count": len(agg)}

    def findings(self, parsed, p):
        out = []
        for a in parsed["alerts"]:
            out.append(FindingDraft(title=f"IDS alert: {a['signature']} (x{a['count']})",
                                    severity=_SEV.get(a["severity"], Severity.low),
                                    attack_technique="T1071", asset=a.get("src_ip") or "",
                                    description=f"From {a.get('src_ip')} to {a.get('dest_ip')}.",
                                    remediation="Triage the source; block if malicious; correlate with host logs.",
                                    evidence=a))
        return out or [FindingDraft(title="No Suricata alerts above threshold", severity=Severity.info)]

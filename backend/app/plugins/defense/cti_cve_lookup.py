"""CTI — recent CVE feed (DEFENSE / Threat intelligence, passive, external API).

Queries the public NVD API via the update module. Operator-initiated outbound
call; no key required (a CO_NVD_API_KEY raises rate limits).
"""
from __future__ import annotations
import json
from ...models import Mode, Severity
from ..base import BasePlugin, ExecResult, FindingDraft, Param, PluginMeta, Step
from ... import updater


class CveLookup(BasePlugin):
    meta = PluginMeta(
        slug="cti_cve", name="CTI: recent CVEs (NVD)", mode=Mode.defense,
        category="Veille CTI (threat intelligence)", privilege="passive", binary=None,
        description="Pull recently published CVEs from NVD to feed vulnerability triage.",
        attack_techniques=[],
        params=[
            Param("days", "Window (days)", "int", required=False, default=7, help="How far back to look."),
            Param("min_cvss", "Min CVSS", "int", required=False, default=7, help="Only surface CVEs at/above this score."),
        ],
        steps=[
            Step("window", "1. Window", "How many days back to fetch newly published CVEs.", ["days", "min_cvss"], "A window + threshold."),
            Step("run", "2. Fetch", "Query NVD and list high-scoring recent CVEs.", [], "Recent CVEs with scores."),
        ],
    )

    def execute_python(self, p):
        res = updater.check_recent_cves(days=int(p.get("days", 7)), limit=50)
        return ExecResult(json.dumps(res), 0 if res.get("ok") else 1, "nvd:recent",
                          simulated=not res.get("ok"))

    def parse(self, raw, p):
        try:
            res = json.loads(raw)
        except json.JSONDecodeError:
            res = {"ok": False, "cves": []}
        if not res.get("ok"):
            # offline/blocked: representative sample so the flow stays usable
            res = {"ok": False, "cves": [
                {"id": "CVE-2026-0001", "cvss": 9.8, "published": "recent"},
                {"id": "CVE-2026-0002", "cvss": 7.5, "published": "recent"}]}
        thr = int(p.get("min_cvss", 7) or 0)
        hi = [c for c in res["cves"] if (c.get("cvss") or 0) >= thr]
        return {"cves": hi, "count": len(hi), "live": res.get("ok", False)}

    def findings(self, parsed, p):
        out = []
        for c in parsed["cves"]:
            score = c.get("cvss") or 0
            sev = Severity.critical if score >= 9 else Severity.high if score >= 7 else Severity.medium
            out.append(FindingDraft(title=f"{c['id']} (CVSS {score})", severity=sev,
                                    description="Recently published; check exposure of affected products.",
                                    remediation="Map to your asset inventory and patch/mitigate if affected.",
                                    evidence=c))
        if not parsed["live"]:
            out.insert(0, FindingDraft(title="NVD feed offline — showing sample CVEs", severity=Severity.info,
                                       description="No outbound access or API error; connect the network to pull live data."))
        return out

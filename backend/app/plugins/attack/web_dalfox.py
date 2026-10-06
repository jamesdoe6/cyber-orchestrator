"""Dalfox — XSS scanner (Web pentest, offensive). T1059.007."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Dalfox(BasePlugin):
    meta = PluginMeta(
        slug="dalfox", name="Dalfox (XSS)", mode=Mode.attack,
        category="Web app pentest", privilege="offensive", binary="dalfox",
        description="Detect reflected/stored XSS on an authorized URL with parameters.",
        attack_techniques=["T1059.007","T1190"],
        params=[Param("target","URL (with param)","string",help="e.g. https://app.example.com/s?q=test")],
        steps=[Step("t","1. Target","Authorized URL with a parameter.",["target"],"A URL."),
               Step("r","2. Scan","Test for XSS.",[],"XSS verdict + PoC.")],
    )
    def build_argv(self,p): return ["dalfox","url",p["target"],"--no-color","--silence"]
    def simulate(self,p): return f"[POC][R] {p.get('target','https://app.example.com/s?q=test')}?q=<script>alert(1)</script>\n"
    def parse(self,raw,p):
        pocs=re.findall(r"\[POC\]\[?\w?\]?\s*(\S+)",raw);return {"pocs":pocs,"count":len(pocs)}
    def findings(self,parsed,p):
        if not parsed["count"]:
            return [FindingDraft(title=f"No XSS confirmed on {p['target']}",severity=Severity.info,attack_technique="T1059.007")]
        return [FindingDraft(title=f"XSS confirmed on {p['target']}",severity=Severity.high,cvss=6.1,
                attack_technique="T1059.007",asset=p["target"],remediation="Context-encode output; CSP; input validation.",
                evidence={"pocs":parsed["pocs"][:5]})]

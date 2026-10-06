"""wafw00f — WAF fingerprinting (Web pentest, active). T1595."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Wafw00f(BasePlugin):
    meta = PluginMeta(
        slug="wafw00f", name="wafw00f (WAF detect)", mode=Mode.attack,
        category="Scan de vulnérabilités", privilege="active", binary="wafw00f",
        description="Detect and fingerprint a Web Application Firewall in front of a site.",
        attack_techniques=["T1595"],
        params=[Param("target","URL","string",help="e.g. https://app.example.com")],
        steps=[Step("t","1. Target","URL to test.",["target"],"A URL."),
               Step("r","2. Detect","Fingerprint any WAF.",[],"WAF vendor (if any).")],
    )
    def build_argv(self,p): return ["wafw00f","-a",p["target"]]
    def simulate(self,p): return f"[+] The site {p.get('target','https://app.example.com')} is behind Cloudflare (Cloudflare Inc.) WAF.\n"
    def parse(self,raw,p):
        m=re.search(r"is behind\s+(.+?)\s+WAF",raw)
        return {"waf":m.group(1).strip() if m else None}
    def findings(self,parsed,p):
        if parsed["waf"]:
            return [FindingDraft(title=f"WAF detected: {parsed['waf']}",severity=Severity.info,
                    attack_technique="T1595",asset=p["target"],description="Tune payloads/rate accordingly.")]
        return [FindingDraft(title="No WAF detected",severity=Severity.low,attack_technique="T1595",asset=p["target"])]

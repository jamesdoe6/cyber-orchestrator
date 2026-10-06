"""Gitleaks — secret scanning in a repo/directory (defense, passive). T1552.001."""
from __future__ import annotations
import json
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Gitleaks(BasePlugin):
    meta = PluginMeta(
        slug="gitleaks", name="Gitleaks (secret scan)", mode=Mode.defense,
        category="Threat hunting", privilege="passive", binary="gitleaks",
        description="Scan a git repo or directory for hardcoded secrets (keys, tokens, passwords).",
        attack_techniques=["T1552.001"],
        params=[Param("target","Repo/dir path","string",help="Path to scan (read-only).")],
        steps=[Step("t","1. Path","Repository/directory to scan.",["target"],"A path."),
               Step("r","2. Scan","Detect committed secrets.",[],"Leaked secrets list.")],
    )
    def build_argv(self,p): return ["gitleaks","detect","--source",p["target"],"--report-format","json","--report-path","/dev/stdout","--no-banner"]
    def simulate(self,p):
        return json.dumps([{"RuleID":"aws-access-token","File":"config/prod.env","Secret":"AKIA...REDACTED","StartLine":12},
                           {"RuleID":"generic-api-key","File":"src/app.js","Secret":"sk_live_REDACTED","StartLine":88}])
    def parse(self,raw,p):
        try: leaks=json.loads(raw[raw.index("["):raw.rindex("]")+1])
        except (ValueError,json.JSONDecodeError): leaks=[]
        return {"leaks":leaks,"count":len(leaks)}
    def findings(self,parsed,p):
        if not parsed["count"]:
            return [FindingDraft(title="No secrets detected",severity=Severity.info,attack_technique="T1552.001")]
        out=[]
        for l in parsed["leaks"][:50]:
            out.append(FindingDraft(title=f"Secret leaked: {l.get('RuleID')} in {l.get('File')}:{l.get('StartLine')}",
                severity=Severity.high,attack_technique="T1552.001",asset=l.get("File",""),
                remediation="Revoke/rotate the secret, purge from git history (BFG/filter-repo), use a secrets manager.",
                evidence={"rule":l.get("RuleID")}))
        return out

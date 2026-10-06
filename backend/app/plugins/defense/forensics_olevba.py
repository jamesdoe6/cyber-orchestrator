"""olevba (oletools) — malicious Office macro analysis (passive). T1059.005."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Olevba(BasePlugin):
    meta = PluginMeta(
        slug="olevba", name="olevba (macro analysis)", mode=Mode.defense,
        category="Analyse de malware / forensics", privilege="passive", binary="olevba",
        description="Extract and analyze VBA macros from Office documents for malicious behavior.",
        attack_techniques=["T1059.005","T1566.001"],
        params=[Param("target","Document path","string",help="Office file to analyze (read-only).")],
        steps=[Step("t","1. Document","Office file to inspect.",["target"],"A document."),
               Step("r","2. Analyze","Extract macros + IOC flags.",[],"Macro verdict.")],
    )
    def build_argv(self,p): return ["olevba",p["target"]]
    def simulate(self,p):
        return ("|AutoExec    |AutoOpen            |Runs when document opened|\n"
                "|Suspicious  |Shell               |May run an executable|\n"
                "|Suspicious  |powershell          |May download/execute|\n"
                "|IOC         |http://evil.example |URL|\n")
    def parse(self,raw,p):
        auto=re.findall(r"\|AutoExec\s*\|([^|]+)\|",raw)
        susp=re.findall(r"\|Suspicious\s*\|([^|]+)\|",raw)
        iocs=re.findall(r"\|IOC\s*\|([^|]+)\|",raw)
        return {"autoexec":[x.strip() for x in auto],"suspicious":[x.strip() for x in susp],"iocs":[x.strip() for x in iocs]}
    def findings(self,parsed,p):
        risky=parsed["autoexec"] or parsed["suspicious"] or parsed["iocs"]
        if not risky:
            return [FindingDraft(title="No macros / no suspicious indicators",severity=Severity.info,asset=p["target"])]
        sev=Severity.critical if (parsed["autoexec"] and (parsed["suspicious"] or parsed["iocs"])) else Severity.high
        return [FindingDraft(title="Malicious-macro indicators in Office document",severity=sev,
                attack_technique="T1059.005",asset=p["target"],
                description=f"AutoExec: {parsed['autoexec']} · Suspicious: {parsed['suspicious']}",
                remediation="Block macros from the internet; detonate in a sandbox; pivot on IOCs.",
                evidence={"autoexec":parsed["autoexec"],"suspicious":parsed["suspicious"],"iocs":parsed["iocs"]})]

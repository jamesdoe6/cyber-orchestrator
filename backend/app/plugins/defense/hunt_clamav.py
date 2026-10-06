"""ClamAV — antivirus scan of a path (defense, passive)."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class ClamAV(BasePlugin):
    meta = PluginMeta(
        slug="clamav", name="ClamAV (AV scan)", mode=Mode.defense,
        category="Analyse de malware / forensics", privilege="passive", binary="clamscan",
        description="Scan a file/directory for known malware signatures with ClamAV.",
        attack_techniques=["T1059"],
        params=[Param("target","Path","string",help="File/directory to scan (read-only)."),
                Param("recursive","Recursive","bool",required=False,default=True,help="Scan directories recursively.")],
        steps=[Step("t","1. Path","File/dir to scan.",["target","recursive"],"A path."),
               Step("r","2. Scan","Match signatures.",[],"Detected malware.")],
    )
    def build_argv(self,p):
        argv=["clamscan","--no-summary"]
        if p.get("recursive",True): argv.append("-r")
        argv.append(p["target"]);return argv
    def simulate(self,p):
        return f"{p.get('target','/tmp')}/invoice.exe: Win.Trojan.Emotet-9 FOUND\n{p.get('target','/tmp')}/clean.pdf: OK\n"
    def parse(self,raw,p):
        hits=re.findall(r"^(.+):\s+(.+)\s+FOUND$",raw,re.M);return {"hits":hits,"count":len(hits)}
    def findings(self,parsed,p):
        if not parsed["count"]:
            return [FindingDraft(title="No malware detected",severity=Severity.info)]
        return [FindingDraft(title=f"Malware detected: {sig}",severity=Severity.critical,attack_technique="T1059",
                asset=fpath,remediation="Isolate host, quarantine the file, begin IR triage.",evidence={"signature":sig})
                for fpath,sig in parsed["hits"]]

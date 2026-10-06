"""chkrootkit — rootkit detection on the local host (defense, passive)."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Chkrootkit(BasePlugin):
    meta = PluginMeta(
        slug="chkrootkit", name="chkrootkit (rootkit scan)", mode=Mode.defense,
        category="Analyse de malware / forensics", privilege="passive", binary="chkrootkit",
        description="Check the local host for signs of known rootkits.",
        attack_techniques=["T1014"],
        params=[Param("confirm","Run local scan","bool",required=False,default=True,help="Scans the LOCAL host.")],
        steps=[Step("c","1. Confirm","Runs on the local host (read-only checks).",["confirm"],"Local scan."),
               Step("r","2. Scan","Check for rootkit indicators.",[],"Infected/clean verdict.")],
    )
    def build_argv(self,p): return ["chkrootkit"]
    def simulate(self,p):
        return ("Checking `ls'... not infected\nChecking `sshd'... not infected\n"
                "Checking `hidden processes'... INFECTED (PID 1337)\nSearching for suspicious files... nothing found\n")
    def parse(self,raw,p):
        infected=re.findall(r"(Checking.+?|Searching.+?)\.\.\.\s*INFECTED(.*)",raw)
        return {"infected":[(a.strip(),b.strip()) for a,b in infected],"count":len(infected)}
    def findings(self,parsed,p):
        if not parsed["count"]:
            return [FindingDraft(title="No rootkit indicators found",severity=Severity.info,attack_technique="T1014")]
        return [FindingDraft(title=f"Rootkit indicator: {chk} {extra}".strip(),severity=Severity.critical,
                attack_technique="T1014",remediation="Treat host as compromised; isolate, image, and rebuild from known-good.")
                for chk,extra in parsed["infected"]]

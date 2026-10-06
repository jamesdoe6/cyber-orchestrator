"""enum4linux-ng — SMB/Windows/AD enumeration (Network, active). T1135/T1087."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Enum4linux(BasePlugin):
    meta = PluginMeta(
        slug="enum4linux", name="enum4linux (SMB/AD enum)", mode=Mode.attack,
        category="Network scan", privilege="active", binary="enum4linux-ng",
        description="Enumerate SMB shares, users, groups and OS info from a Windows/Samba host.",
        attack_techniques=["T1135","T1087.002","T1018"],
        params=[Param("target","Target host","string",help="Windows/Samba host IP in scope.")],
        steps=[Step("t","1. Target","Host to enumerate (in scope).",["target"],"A host."),
               Step("r","2. Enumerate","Collect shares/users/groups.",[],"SMB/AD inventory.")],
    )
    def build_argv(self,p): return ["enum4linux-ng","-A",p["target"]]
    def simulate(self,p):
        return ("[+] OS: Windows Server 2019\n[+] Share: ADMIN$\n[+] Share: C$\n[+] Share: HR_Docs (READ)\n"
                "[+] User: administrator\n[+] User: jdoe\n[+] User: svc_backup\n")
    def parse(self,raw,p):
        shares=re.findall(r"Share:\s*(\S+)",raw);users=re.findall(r"User:\s*(\S+)",raw)
        osm=re.search(r"OS:\s*(.+)",raw)
        return {"os":osm.group(1).strip() if osm else None,"shares":shares,"users":users}
    def findings(self,parsed,p):
        out=[]
        if parsed["os"]: out.append(FindingDraft(title=f"OS: {parsed['os']} on {p['target']}",severity=Severity.info,attack_technique="T1018",asset=p["target"]))
        if parsed["shares"]:
            readable=[s for s in parsed["shares"] if s not in ("ADMIN$","C$","IPC$")]
            out.append(FindingDraft(title=f"{len(parsed['shares'])} SMB share(s) on {p['target']}",
                severity=Severity.medium if readable else Severity.low,attack_technique="T1135",asset=p["target"],
                description="Accessible shares can expose sensitive files.",evidence={"shares":parsed["shares"]}))
        if parsed["users"]:
            out.append(FindingDraft(title=f"{len(parsed['users'])} account(s) enumerated via SMB",
                severity=Severity.medium,attack_technique="T1087.002",asset=p["target"],
                description="Null/guest session user enumeration aids password attacks.",evidence={"users":parsed["users"]}))
        return out

"""NetExec (CrackMapExec successor) — SMB/AD auth & enumeration (offensive). T1021.002/T1110."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class NetExec(BasePlugin):
    meta = PluginMeta(
        slug="netexec", name="NetExec (SMB/AD)", mode=Mode.attack,
        category="Exploitation", privilege="offensive", binary="nxc",
        description="Authenticate and enumerate across SMB/AD hosts; validate credentials at scale.",
        attack_techniques=["T1021.002","T1110","T1087.002"],
        params=[Param("target","Target/range","string",help="Host or CIDR in scope."),
                Param("username","Username","string",help="Account to test."),
                Param("password","Password","string",help="Password (or hash with -H upstream)."),
                Param("protocol","Protocol","choice",default="smb",choices=["smb","winrm","ldap","ssh","mssql"],help="Protocol module.")],
        steps=[Step("t","1. Target & proto","Host/range (in scope) and protocol.",["target","protocol"],"Target+proto."),
               Step("c","2. Credentials","Account to validate.",["username","password"],"Creds."),
               Step("r","3. Run","Authenticate and enumerate.",[],"Auth result + access level.")],
    )
    def build_argv(self,p):
        return ["nxc",p.get("protocol","smb"),p["target"],"-u",p["username"],"-p",p["password"]]
    def simulate(self,p):
        return f"SMB  {p.get('target','192.0.2.10')}  445  DC01  [+] ACME\\{p.get('username','jdoe')}:**** (Pwn3d!)\n"
    def parse(self,raw,p):
        ok=bool(re.search(r"\[\+\]",raw));admin="(Pwn3d!)" in raw or "Pwn3d" in raw
        return {"authenticated":ok,"admin":admin}
    def findings(self,parsed,p):
        if not parsed["authenticated"]:
            return [FindingDraft(title=f"Credentials rejected on {p['target']}",severity=Severity.info,attack_technique="T1110")]
        sev=Severity.critical if parsed["admin"] else Severity.high
        return [FindingDraft(title=f"Valid credentials on {p['target']}"+(" with ADMIN access" if parsed["admin"] else ""),
                severity=sev,cvss=9.0 if parsed["admin"] else 7.0,attack_technique="T1021.002",asset=p["target"],
                remediation="Rotate credentials; enforce least privilege; monitor SMB logons; LAPS for local admins.",
                evidence={"admin":parsed["admin"]})]

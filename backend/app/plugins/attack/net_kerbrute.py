"""Kerbrute — AD username enumeration & password spraying via Kerberos (offensive). T1110.003/T1087.002."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Kerbrute(BasePlugin):
    meta = PluginMeta(
        slug="kerbrute", name="Kerbrute (AD users/spray)", mode=Mode.attack,
        category="Brute force / cracking", privilege="offensive", binary="kerbrute",
        description="Enumerate valid AD usernames (and optionally spray a password) via Kerberos pre-auth.",
        attack_techniques=["T1087.002","T1110.003"],
        params=[Param("target","Domain controller","string",help="DC host/IP in scope."),
                Param("domain","AD domain","string",help="e.g. acme.local"),
                Param("userlist","User list path","string",help="Path to a username list on the VM."),
                Param("password","Spray password","string",required=False,default="",help="Optional single password to spray.")],
        steps=[Step("t","1. DC & domain","Domain controller and AD domain (in scope).",["target","domain"],"DC+domain."),
               Step("u","2. Users","Username list (and optional spray password).",["userlist","password"],"User source."),
               Step("r","3. Run","Enumerate valid users / spray.",[],"Valid users / hits.")],
    )
    def build_argv(self,p):
        if p.get("password"):
            return ["kerbrute","passwordspray","-d",p["domain"],"--dc",p["target"],p["userlist"],p["password"]]
        return ["kerbrute","userenum","-d",p["domain"],"--dc",p["target"],p["userlist"]]
    def simulate(self,p):
        return ("[+] VALID USERNAME:\t jdoe@acme.local\n[+] VALID USERNAME:\t svc_sql@acme.local\n"
                +("[+] VALID LOGIN:\t jdoe@acme.local:Spring2026!\n" if p.get("password") else ""))
    def parse(self,raw,p):
        users=re.findall(r"VALID USERNAME:\s*(\S+)",raw);logins=re.findall(r"VALID LOGIN:\s*(\S+)",raw)
        return {"users":users,"logins":logins}
    def findings(self,parsed,p):
        out=[]
        if parsed["users"]:
            out.append(FindingDraft(title=f"{len(parsed['users'])} valid AD username(s) enumerated",severity=Severity.medium,
                attack_technique="T1087.002",asset=p["target"],evidence={"users":parsed["users"][:40]}))
        for l in parsed["logins"]:
            out.append(FindingDraft(title=f"Valid AD credential via spraying: {l.split(':')[0]}",severity=Severity.critical,
                cvss=8.8,attack_technique="T1110.003",asset=p["target"],
                remediation="Enforce strong passwords, MFA, lockout thresholds; alert on spraying patterns."))
        return out or [FindingDraft(title="No valid users found",severity=Severity.info,attack_technique="T1087.002")]

"""Holehe — which sites an email is registered on (OSINT, passive). T1589.002."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Holehe(BasePlugin):
    meta = PluginMeta(
        slug="holehe", name="Holehe (email → accounts)", mode=Mode.attack,
        category="Reconnaissance / OSINT", privilege="passive", binary="holehe",
        description="Check which online services an email address is registered on (no password reset sent).",
        attack_techniques=["T1589.002"],
        params=[Param("target","Email","string",help="Email address to profile.")],
        steps=[Step("t","1. Email","Email to check against services.",["target"],"An email."),
               Step("r","2. Check","List services where it is registered.",[],"Registered services.")],
    )
    def build_argv(self,p): return ["holehe","--only-used",p["target"]]
    def simulate(self,p):
        return "[+] github.com\n[+] twitter.com\n[+] spotify.com\n[+] adobe.com\n"
    def parse(self,raw,p):
        sites=re.findall(r"\[\+\]\s*(\S+)",raw);return {"sites":sites,"count":len(sites)}
    def findings(self,parsed,p):
        if not parsed["count"]: return []
        return [FindingDraft(title=f"Email {p['target']} registered on {parsed['count']} service(s)",
                severity=Severity.low,attack_technique="T1589.002",asset=p["target"],
                description="Service footprint widens phishing/credential-stuffing surface.",
                evidence={"services":parsed["sites"][:40]})]

"""Subfinder — fast passive subdomain discovery (OSINT, passive). T1590.002."""
from __future__ import annotations
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Subfinder(BasePlugin):
    meta = PluginMeta(
        slug="subfinder", name="Subfinder (subdomains)", mode=Mode.attack,
        category="Reconnaissance / OSINT", privilege="passive", binary="subfinder",
        description="Passive subdomain enumeration from dozens of public sources (ProjectDiscovery).",
        attack_techniques=["T1590.002"],
        params=[Param("target", "Domain", "string", help="Root domain, e.g. example.com.")],
        steps=[Step("t","1. Domain","Root domain to enumerate (passive, OSINT only).",["target"],"A domain."),
               Step("r","2. Enumerate","Collect subdomains from public sources.",[],"Subdomain list.")],
    )
    def build_argv(self,p): return ["subfinder","-silent","-d",p["target"]]
    def simulate(self,p):
        d=p.get("target","example.com");return "\n".join([f"www.{d}",f"api.{d}",f"dev.{d}",f"vpn.{d}",f"mail.{d}"])
    def parse(self,raw,p):
        names=sorted({l.strip() for l in raw.splitlines() if l.strip() and "." in l})
        return {"subdomains":names,"count":len(names)}
    def findings(self,parsed,p):
        if not parsed["count"]: return []
        return [FindingDraft(title=f"{parsed['count']} subdomain(s) for {p['target']}",severity=Severity.info,
                attack_technique="T1590.002",asset=p["target"],evidence={"subdomains":parsed["subdomains"][:80]})]

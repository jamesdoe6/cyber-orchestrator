"""OWASP Amass subdomain enumeration (ATTACK / Reconnaissance, passive). ATT&CK T1590.002."""
from __future__ import annotations
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Amass(BasePlugin):
    meta = PluginMeta(
        slug="amass", name="Amass (subdomains)", mode=Mode.attack,
        category="Reconnaissance / OSINT", privilege="passive", binary="amass",
        description="Passive subdomain enumeration and external attack-surface mapping.",
        attack_techniques=["T1590.002"],
        params=[Param("target", "Domain", "string", help="Root domain, e.g. example.com.")],
        steps=[
            Step("target", "1. Domain", "Root domain to enumerate subdomains for (passive mode, OSINT only).", ["target"], "A domain."),
            Step("run", "2. Enumerate", "Run amass in passive mode and list discovered names.", [], "Subdomain list."),
        ],
    )

    def build_argv(self, p):
        return ["amass", "enum", "-passive", "-d", p["target"]]

    def simulate(self, p):
        d = p.get("target", "example.com")
        return "\n".join([f"www.{d}", f"api.{d}", f"staging.{d}", f"vpn.{d}"])

    def parse(self, raw, p):
        names = sorted({l.strip() for l in raw.splitlines() if l.strip() and "." in l and " " not in l.strip()})
        return {"subdomains": names, "count": len(names)}

    def findings(self, parsed, p):
        if not parsed["count"]:
            return []
        return [FindingDraft(title=f"{parsed['count']} subdomain(s) for {p['target']}",
                             severity=Severity.info, attack_technique="T1590.002", asset=p["target"],
                             evidence={"subdomains": parsed["subdomains"][:60]})]

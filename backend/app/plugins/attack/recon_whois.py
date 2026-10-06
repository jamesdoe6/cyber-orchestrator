"""WHOIS registration lookup (ATTACK / Recon, passive). ATT&CK T1596."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Whois(BasePlugin):
    meta = PluginMeta(
        slug="whois", name="WHOIS lookup", mode=Mode.attack,
        category="Reconnaissance / OSINT", privilege="passive", binary="whois",
        description="Registration / ownership data for a domain or IP from public WHOIS.",
        attack_techniques=["T1596"],
        params=[Param("target", "Domain or IP", "string", help="Domain or IP to look up.")],
        steps=[
            Step("target", "1. Target", "Domain or IP to query in public WHOIS registries.", ["target"], "A domain/IP."),
            Step("run", "2. Lookup", "Fetch registration details.", [], "Registrar, dates, nameservers."),
        ],
    )

    def build_argv(self, p):
        return ["whois", p["target"]]

    def simulate(self, p):
        return ("Domain Name: EXAMPLE.COM\nRegistrar: ICANN Reserved\n"
                "Creation Date: 1995-08-14T04:00:00Z\nName Server: A.IANA-SERVERS.NET\n")

    def parse(self, raw, p):
        fields = {}
        for key in ("Registrar", "Creation Date", "Registry Expiry Date", "Name Server", "Registrant Organization"):
            m = re.findall(rf"(?im)^{key}:\s*(.+)$", raw)
            if m:
                fields[key] = m if key == "Name Server" else m[0]
        return {"fields": fields}

    def findings(self, parsed, p):
        return [FindingDraft(title=f"WHOIS profile for {p['target']}", severity=Severity.info,
                             attack_technique="T1596", asset=p["target"], evidence=parsed["fields"])]

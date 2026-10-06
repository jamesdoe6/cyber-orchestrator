"""theHarvester OSINT (ATTACK / Reconnaissance, passive). ATT&CK T1589, T1590."""
from __future__ import annotations
import json, re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class TheHarvester(BasePlugin):
    meta = PluginMeta(
        slug="theharvester", name="theHarvester (OSINT)", mode=Mode.attack,
        category="Reconnaissance / OSINT", privilege="passive", binary="theHarvester",
        description="Harvest emails, subdomains and hosts from public sources for a domain.",
        attack_techniques=["T1589", "T1590", "T1596"],
        params=[
            Param("target", "Domain", "string", help="Domain to profile, e.g. example.com (OSINT, no direct contact)."),
            Param("sources", "Sources", "string", required=False, default="bing,crtsh,duckduckgo",
                  help="Comma-separated data sources passed to -b."),
            Param("limit", "Result limit", "int", required=False, default=200, help="-l results per source."),
        ],
        steps=[
            Step("target", "1. Domain", "Enter the domain to profile from public data. No packets are sent to the target.", ["target"], "A domain."),
            Step("sources", "2. Sources", "Pick public data sources. More sources = broader but slower.", ["sources", "limit"], "Source list."),
            Step("run", "3. Collect", "Query the sources and aggregate emails/subdomains/hosts.", [], "Emails, subdomains and hosts."),
        ],
    )

    def build_argv(self, p):
        return ["theHarvester", "-d", p["target"], "-b", p.get("sources", "bing"),
                "-l", str(p.get("limit", 200)), "-f", "/dev/stdout"]

    def simulate(self, p):
        d = p.get("target", "example.com")
        return json.dumps({"emails": [f"admin@{d}", f"info@{d}"],
                           "hosts": [f"www.{d}", f"mail.{d}", f"vpn.{d}"]})

    def parse(self, raw, p):
        emails, hosts = set(), set()
        try:
            data = json.loads(raw[raw.index("{"):raw.rindex("}") + 1])
            emails.update(data.get("emails", [])); hosts.update(data.get("hosts", []))
        except (ValueError, json.JSONDecodeError):
            emails.update(re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", raw))
        return {"emails": sorted(emails), "hosts": sorted(hosts),
                "email_count": len(emails), "host_count": len(hosts)}

    def findings(self, parsed, p):
        out = []
        if parsed["emails"]:
            out.append(FindingDraft(
                title=f"{parsed['email_count']} email(s) exposed via OSINT for {p['target']}",
                severity=Severity.low, attack_technique="T1589", asset=p["target"],
                description="Addresses discoverable in public sources widen the phishing surface.",
                evidence={"emails": parsed["emails"][:25]}))
        if parsed["hosts"]:
            out.append(FindingDraft(
                title=f"{parsed['host_count']} subdomain/host(s) discovered for {p['target']}",
                severity=Severity.info, attack_technique="T1590", asset=p["target"],
                evidence={"hosts": parsed["hosts"][:50]}))
        return out

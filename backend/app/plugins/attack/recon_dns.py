"""DNS reconnaissance via dnsutils (ATTACK / Recon, passive). ATT&CK T1590.002."""
from __future__ import annotations
from ...models import Mode, Severity
from ..base import BasePlugin, ExecResult, FindingDraft, Param, PluginMeta, Step
import shutil, subprocess


class DnsRecon(BasePlugin):
    meta = PluginMeta(
        slug="dns_recon", name="DNS recon (dig)", mode=Mode.attack,
        category="Reconnaissance / OSINT", privilege="passive", binary="dig",
        description="Enumerate DNS records (A, MX, NS, TXT) for a domain via public resolvers.",
        attack_techniques=["T1590.002"],
        params=[
            Param("target", "Domain", "string", help="Domain to resolve, e.g. example.com."),
            Param("resolver", "Resolver", "string", required=False, default="1.1.1.1",
                  help="Public DNS resolver to query."),
        ],
        steps=[
            Step("target", "1. Domain", "Domain whose DNS records to enumerate (queries a public resolver, not the target).", ["target", "resolver"], "A domain."),
            Step("run", "2. Resolve", "Query A/AAAA/MX/NS/TXT records.", [], "DNS records by type."),
        ],
    )
    _TYPES = ["A", "AAAA", "MX", "NS", "TXT"]

    def build_argv(self, p):  # multi-query handled in execute via a single dig ANY fallback
        return ["dig", "+nocmd", "+noall", "+answer", f"@{p.get('resolver','1.1.1.1')}", p["target"], "ANY"]

    def execute_python(self, p):  # dig per-type for broad resolver compatibility
        if not shutil.which("dig"):
            return ExecResult(self.simulate(p), 0, "dig (simulated)", simulated=True)
        out = []
        for t in self._TYPES:
            r = subprocess.run(["dig", "+nocmd", "+noall", "+answer",
                                f"@{p.get('resolver','1.1.1.1')}", p["target"], t],
                               capture_output=True, text=True, timeout=30, check=False)
            out.append(r.stdout)
        return ExecResult("".join(out), 0, f"dig {p['target']} {'/'.join(self._TYPES)}")

    def simulate(self, p):
        d = p.get("target", "example.com")
        return (f"{d}. 300 IN A 93.184.216.34\n{d}. 300 IN MX 10 mail.{d}.\n"
                f"{d}. 300 IN NS ns1.{d}.\n{d}. 300 IN TXT \"v=spf1 include:_spf.{d} -all\"\n")

    def parse(self, raw, p):
        records = {}
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[3] in self._TYPES:
                records.setdefault(parts[3], []).append(" ".join(parts[4:]))
        return {"records": records, "types": sorted(records)}

    def findings(self, parsed, p):
        out = [FindingDraft(title=f"DNS records enumerated for {p['target']} ({', '.join(parsed['types']) or 'none'})",
                            severity=Severity.info, attack_technique="T1590.002", asset=p["target"],
                            evidence=parsed["records"])]
        txt = " ".join(parsed["records"].get("TXT", []))
        if "spf1" in txt and "-all" not in txt and "~all" not in txt:
            out.append(FindingDraft(title=f"Weak/again permissive SPF policy on {p['target']}",
                                    severity=Severity.low, attack_technique="T1589", asset=p["target"],
                                    description="SPF record does not end in -all/~all; spoofing surface.",
                                    evidence={"txt": txt}))
        return out

"""Waybackurls — URLs for a domain from the Wayback Machine (OSINT, passive). T1596."""
from __future__ import annotations
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Waybackurls(BasePlugin):
    meta = PluginMeta(
        slug="waybackurls", name="Waybackurls (archived URLs)", mode=Mode.attack,
        category="Reconnaissance / OSINT", privilege="passive", binary="waybackurls",
        description="Historical URLs/endpoints for a domain from public web archives.",
        attack_techniques=["T1596","T1593.002"],
        params=[Param("target","Domain","string",help="Domain, e.g. example.com.")],
        steps=[Step("t","1. Domain","Domain to pull archived URLs for.",["target"],"A domain."),
               Step("r","2. Fetch","Collect historical endpoints.",[],"URL list (endpoints, params).")],
    )
    def build_argv(self,p): return ["waybackurls",p["target"]]
    def simulate(self,p):
        d=p.get("target","example.com")
        return "\n".join([f"https://{d}/login",f"https://{d}/admin?debug=1",f"https://{d}/api/v1/users",f"https://{d}/old/backup.zip"])
    def parse(self,raw,p):
        urls=sorted({l.strip() for l in raw.splitlines() if l.strip().startswith("http")})
        interesting=[u for u in urls if any(k in u.lower() for k in ("admin","backup",".zip",".sql","debug","token","key","config",".git"))]
        return {"urls":urls,"count":len(urls),"interesting":interesting}
    def findings(self,parsed,p):
        out=[FindingDraft(title=f"{parsed['count']} archived URL(s) for {p['target']}",severity=Severity.info,
             attack_technique="T1596",asset=p["target"],evidence={"sample":parsed["urls"][:40]})]
        if parsed["interesting"]:
            out.append(FindingDraft(title=f"{len(parsed['interesting'])} potentially sensitive archived URL(s)",
                severity=Severity.low,attack_technique="T1596",asset=p["target"],
                description="Archived endpoints referencing admin/backup/secrets — verify they are not still live.",
                evidence={"urls":parsed["interesting"][:25]}))
        return out

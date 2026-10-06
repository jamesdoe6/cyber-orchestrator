"""httpx — HTTP probing & fingerprinting (ProjectDiscovery) (active). T1595."""
from __future__ import annotations
import json
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class HttpxProbe(BasePlugin):
    meta = PluginMeta(
        slug="httpx_probe", name="httpx (HTTP probe)", mode=Mode.attack,
        category="Scan de vulnérabilités", privilege="active", binary="httpx",
        description="Probe a host/URL: status, title, tech, server, TLS — triage live web surfaces.",
        attack_techniques=["T1595","T1592"],
        params=[Param("target","Host or URL","string",help="e.g. app.example.com or https://app.example.com")],
        steps=[Step("t","1. Target","Host/URL to probe (in scope).",["target"],"A target."),
               Step("r","2. Probe","Fetch status/title/tech.",[],"HTTP fingerprint.")],
    )
    def build_argv(self,p): return ["httpx","-silent","-json","-title","-tech-detect","-status-code","-server","-u",p["target"]]
    def simulate(self,p):
        return json.dumps({"url":"https://app.example.com","status_code":200,"title":"ACME App",
                           "webserver":"nginx","tech":["Nginx","React","Cloudflare"]})
    def parse(self,raw,p):
        rows=[]
        for line in raw.splitlines():
            line=line.strip()
            if line.startswith("{"):
                try: rows.append(json.loads(line))
                except json.JSONDecodeError: pass
        return {"rows":rows}
    def findings(self,parsed,p):
        out=[]
        for r in parsed["rows"]:
            out.append(FindingDraft(title=f"{r.get('url')} [{r.get('status_code')}] {r.get('title','')}".strip(),
                severity=Severity.info,attack_technique="T1595",asset=r.get("url",p["target"]),
                evidence={"server":r.get("webserver"),"tech":r.get("tech")}))
        return out or [FindingDraft(title="No live HTTP response",severity=Severity.info)]

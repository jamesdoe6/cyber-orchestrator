"""WPScan — WordPress vulnerability scanner (Web pentest, active). T1595.002."""
from __future__ import annotations
import json
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class WPScan(BasePlugin):
    meta = PluginMeta(
        slug="wpscan", name="WPScan (WordPress)", mode=Mode.attack,
        category="Web app pentest", privilege="active", binary="wpscan",
        description="Enumerate WordPress version, plugins, users and known vulnerabilities.",
        attack_techniques=["T1595.002","T1087"],
        params=[Param("target","WordPress URL","string",help="e.g. https://blog.example.com"),
                Param("enumerate","Enumerate","choice",required=False,default="vp,u",
                      choices=["vp","vp,u","ap,u","vp,vt,u"],help="vp=vuln plugins, u=users, ap=all plugins, vt=vuln themes.")],
        steps=[Step("t","1. Target","WordPress site URL (in scope).",["target"],"A URL."),
               Step("e","2. Enumerate","What to enumerate.",["enumerate"],"Enum options."),
               Step("r","3. Scan","Run and collect findings.",[],"Version, plugins, users, vulns.")],
    )
    def build_argv(self,p):
        return ["wpscan","--url",p["target"],"--enumerate",p.get("enumerate","vp,u"),"-f","json","--no-banner"]
    def simulate(self,p):
        return json.dumps({"version":{"number":"5.2","vulnerabilities":[{"title":"WP 5.2 XSS"}]},
                           "plugins":{"contact-form-7":{"version":{"number":"5.0"},"vulnerabilities":[{"title":"CF7 upload RCE"}]}},
                           "users":{"admin":{},"editor":{}}})
    def parse(self,raw,p):
        try: d=json.loads(raw[raw.index("{"):raw.rindex("}")+1])
        except (ValueError,json.JSONDecodeError): return {"version":None,"plugins":{},"users":[],"vulns":[]}
        vulns=[]
        v=d.get("version") or {}
        for x in v.get("vulnerabilities",[]): vulns.append(("core",x.get("title")))
        for name,pl in (d.get("plugins") or {}).items():
            for x in pl.get("vulnerabilities",[]): vulns.append((name,x.get("title")))
        return {"version":(v.get("number")),"users":list((d.get("users") or {}).keys()),"vulns":vulns}
    def findings(self,parsed,p):
        out=[FindingDraft(title=f"WordPress {parsed['version'] or '?'} detected",severity=Severity.info,
             attack_technique="T1595.002",asset=p["target"])]
        if parsed["users"]:
            out.append(FindingDraft(title=f"{len(parsed['users'])} WP user(s) enumerated",severity=Severity.low,
                attack_technique="T1087",asset=p["target"],evidence={"users":parsed["users"]}))
        for comp,title in parsed["vulns"]:
            out.append(FindingDraft(title=f"WP vuln ({comp}): {title}",severity=Severity.high,
                attack_technique="T1190",asset=p["target"]))
        return out

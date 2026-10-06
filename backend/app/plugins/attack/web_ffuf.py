"""ffuf — content/directory discovery (Web pentest, active). T1595.003."""
from __future__ import annotations
import json
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Ffuf(BasePlugin):
    meta = PluginMeta(
        slug="ffuf", name="ffuf (content discovery)", mode=Mode.attack,
        category="Web app pentest", privilege="active", binary="ffuf",
        description="Fuzz for hidden directories/files on an authorized web app.",
        attack_techniques=["T1595.003"],
        params=[Param("target","Base URL","string",help="Use FUZZ keyword, e.g. https://app.example.com/FUZZ"),
                Param("wordlist","Wordlist path","string",default="/usr/share/wordlists/dirb/common.txt",help="Dir/file wordlist."),
                Param("mc","Match codes","string",required=False,default="200,204,301,302,307,401,403",help="HTTP codes to report.")],
        steps=[Step("t","1. Target","URL with the FUZZ keyword (in scope).",["target"],"A fuzz URL."),
               Step("w","2. Wordlist & codes","Wordlist and which HTTP codes to keep.",["wordlist","mc"],"Config."),
               Step("r","3. Fuzz","Run and list discovered paths.",[],"Found endpoints.")],
    )
    def build_argv(self,p):
        t=p["target"]; t=t if "FUZZ" in t else t.rstrip("/")+"/FUZZ"
        return ["ffuf","-u",t,"-w",p["wordlist"],"-mc",p.get("mc","200,301,302,401,403"),"-of","json","-o","/dev/stdout","-s"]
    def simulate(self,p):
        return json.dumps({"results":[{"input":{"FUZZ":"admin"},"url":"https://app.example.com/admin","status":301},
                                       {"input":{"FUZZ":".git"},"url":"https://app.example.com/.git","status":200}]})
    def parse(self,raw,p):
        try: res=json.loads(raw[raw.index("{"):raw.rindex("}")+1]).get("results",[])
        except (ValueError,json.JSONDecodeError): res=[]
        return {"hits":[{"url":r.get("url"),"status":r.get("status")} for r in res],"count":len(res)}
    def findings(self,parsed,p):
        out=[]
        for h in parsed["hits"]:
            sev=Severity.medium if any(k in (h["url"] or "").lower() for k in ("admin",".git","backup","config",".env")) else Severity.info
            out.append(FindingDraft(title=f"Discovered {h['url']} [{h['status']}]",severity=sev,
                       attack_technique="T1595.003",asset=h["url"]))
        return out or [FindingDraft(title="No content discovered",severity=Severity.info)]

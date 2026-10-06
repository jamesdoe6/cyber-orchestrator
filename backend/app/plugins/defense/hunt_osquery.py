"""osquery — query host state with SQL (defense, passive). T1518."""
from __future__ import annotations
import json
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step

_PRESETS={
 "listening_ports":"SELECT DISTINCT address,port,p.name FROM listening_ports l JOIN processes p ON l.pid=p.pid;",
 "logged_in_users":"SELECT user,host,time FROM logged_in_users;",
 "startup_items":"SELECT name,path,source FROM startup_items;",
 "suid_bin":"SELECT path,permissions FROM suid_bin;",
}


class OSQuery(BasePlugin):
    meta = PluginMeta(
        slug="osquery", name="osquery (host query)", mode=Mode.defense,
        category="Threat hunting", privilege="passive", binary="osqueryi",
        description="Query local host state (listening ports, users, startup items, SUID binaries) via SQL.",
        attack_techniques=["T1518","T1049"],
        params=[Param("preset","Query","choice",default="listening_ports",choices=list(_PRESETS),help="Preset host query."),
                Param("query","Custom SQL","string",required=False,default="",help="Optional custom osquery SQL (overrides preset).")],
        steps=[Step("q","1. Query","Pick a preset or write SQL.",["preset","query"],"A query."),
               Step("r","2. Run","Execute against the local host.",[],"Host state rows.")],
    )
    def build_argv(self,p):
        sql=(p.get("query") or "").strip() or _PRESETS[p.get("preset","listening_ports")]
        return ["osqueryi","--json",sql]
    def simulate(self,p):
        return json.dumps([{"address":"0.0.0.0","port":"22","name":"sshd"},
                           {"address":"0.0.0.0","port":"3389","name":"xrdp"},
                           {"address":"127.0.0.1","port":"5432","name":"postgres"}])
    def parse(self,raw,p):
        try: rows=json.loads(raw[raw.index("["):raw.rindex("]")+1])
        except (ValueError,json.JSONDecodeError): rows=[]
        return {"rows":rows,"count":len(rows)}
    def findings(self,parsed,p):
        out=[FindingDraft(title=f"osquery returned {parsed['count']} row(s)",severity=Severity.info,
             attack_technique="T1518",evidence={"rows":parsed["rows"][:30]})]
        for r in parsed["rows"]:
            if r.get("port") in ("3389","23","445") and r.get("address","").startswith("0.0.0.0"):
                out.append(FindingDraft(title=f"Sensitive service on all interfaces: {r.get('name')}:{r.get('port')}",
                    severity=Severity.medium,remediation="Bind to localhost or restrict via firewall."))
        return out

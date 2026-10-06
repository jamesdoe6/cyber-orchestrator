"""Trivy — filesystem/dependency/container vulnerability scan (defense, passive). T1518.001."""
from __future__ import annotations
import json
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step

_SEV={"CRITICAL":Severity.critical,"HIGH":Severity.high,"MEDIUM":Severity.medium,"LOW":Severity.low,"UNKNOWN":Severity.info}


class Trivy(BasePlugin):
    meta = PluginMeta(
        slug="trivy", name="Trivy (vuln scan)", mode=Mode.defense,
        category="Gestion de vulnérabilités", privilege="passive", binary="trivy",
        description="Scan a filesystem path or container image for known CVEs in OS/app dependencies.",
        attack_techniques=["T1518.001"],
        params=[Param("scan_type","Scan type","choice",default="fs",choices=["fs","image"],help="fs=directory, image=container image."),
                Param("target","Path or image","string",help="Directory path, or image name (e.g. nginx:1.24).")],
        steps=[Step("t","1. Target","Filesystem path or image to scan.",["scan_type","target"],"A target."),
               Step("r","2. Scan","Enumerate CVEs by severity.",[],"Vulnerable packages.")],
    )
    def build_argv(self,p): return ["trivy",p.get("scan_type","fs"),"--quiet","--format","json",p["target"]]
    def simulate(self,p):
        return json.dumps({"Results":[{"Target":"package-lock.json","Vulnerabilities":[
            {"VulnerabilityID":"CVE-2024-0001","PkgName":"lodash","InstalledVersion":"4.17.11","Severity":"HIGH","Title":"Prototype pollution"},
            {"VulnerabilityID":"CVE-2023-9999","PkgName":"openssl","InstalledVersion":"1.1.1","Severity":"CRITICAL","Title":"RCE"}]}]})
    def parse(self,raw,p):
        vulns=[]
        try:
            for res in json.loads(raw[raw.index("{"):raw.rindex("}")+1]).get("Results",[]):
                for v in (res.get("Vulnerabilities") or []):
                    vulns.append({"id":v.get("VulnerabilityID"),"pkg":v.get("PkgName"),
                                  "ver":v.get("InstalledVersion"),"sev":v.get("Severity"),"title":v.get("Title")})
        except (ValueError,json.JSONDecodeError): pass
        return {"vulns":vulns,"count":len(vulns)}
    def findings(self,parsed,p):
        if not parsed["count"]:
            return [FindingDraft(title="No known vulnerabilities found",severity=Severity.info,attack_technique="T1518.001")]
        out=[]
        for v in sorted(parsed["vulns"],key=lambda x:["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"].index(x["sev"] or "UNKNOWN"))[:60]:
            out.append(FindingDraft(title=f"{v['id']} in {v['pkg']} {v['ver']} — {v['title']}",
                severity=_SEV.get(v["sev"],Severity.info),attack_technique="T1518.001",asset=f"{v['pkg']} {v['ver']}",
                remediation="Upgrade the affected package to a fixed version."))
        return out

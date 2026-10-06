"""sslscan — TLS/SSL configuration audit (Web pentest, active)."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class SSLScan(BasePlugin):
    meta = PluginMeta(
        slug="sslscan", name="sslscan (TLS audit)", mode=Mode.attack,
        category="Web app pentest", privilege="active", binary="sslscan",
        description="Audit a host's TLS/SSL: protocol versions, weak ciphers, cert validity.",
        attack_techniques=["T1595"],
        params=[Param("target","Host:port","string",help="e.g. app.example.com:443")],
        steps=[Step("t","1. Target","Host (and port) to audit.",["target"],"A host:port."),
               Step("r","2. Audit","Enumerate protocols/ciphers.",[],"TLS posture findings.")],
    )
    def build_argv(self,p): return ["sslscan","--no-colour",p["target"]]
    def simulate(self,p):
        return ("Accepted  SSLv3    112 bits  DES-CBC3-SHA\nAccepted  TLSv1.0  128 bits  AES128-SHA\n"
                "Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384\n")
    def parse(self,raw,p):
        protos=set(re.findall(r"(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3)",raw))
        weak=[x for x in protos if x in ("SSLv2","SSLv3","TLSv1.0","TLSv1.1")]
        return {"protocols":sorted(protos),"weak":sorted(weak)}
    def findings(self,parsed,p):
        out=[FindingDraft(title=f"TLS protocols: {', '.join(parsed['protocols']) or 'none'}",severity=Severity.info,
             attack_technique="T1595",asset=p["target"])]
        if parsed["weak"]:
            out.append(FindingDraft(title=f"Weak/deprecated TLS enabled: {', '.join(parsed['weak'])}",
                severity=Severity.medium,attack_technique="T1595",asset=p["target"],
                remediation="Disable SSLv2/3 and TLS 1.0/1.1; require TLS 1.2+ with modern ciphers.",
                evidence={"weak":parsed["weak"]}))
        return out

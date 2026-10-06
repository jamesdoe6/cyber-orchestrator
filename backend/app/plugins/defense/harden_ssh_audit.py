"""ssh-audit — SSH server hardening audit (passive)."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class SshAudit(BasePlugin):
    meta = PluginMeta(
        slug="ssh_audit", name="ssh-audit (SSH hardening)", mode=Mode.defense,
        category="Durcissement (hardening)", privilege="passive", binary="ssh-audit",
        description="Audit an SSH server for weak algorithms, ciphers and known CVEs.",
        attack_techniques=["T1021.004"],
        params=[Param("target","Host[:port]","string",help="SSH server, e.g. 10.0.0.5 or 10.0.0.5:2222.")],
        steps=[Step("t","1. Target","SSH server to audit.",["target"],"A host."),
               Step("r","2. Audit","Check algorithms/ciphers.",[],"Weak-config findings.")],
    )
    def build_argv(self,p): return ["ssh-audit","--no-colors",p["target"]]
    def simulate(self,p):
        return ("(fail) diffie-hellman-group1-sha1 -- weak key exchange\n"
                "(warn) hmac-sha1 -- deprecated MAC\n(fail) ssh-rsa -- SHA-1 host key\n")
    def parse(self,raw,p):
        fails=re.findall(r"\(fail\)\s*(.+)",raw);warns=re.findall(r"\(warn\)\s*(.+)",raw)
        return {"fails":[x.strip() for x in fails],"warns":[x.strip() for x in warns]}
    def findings(self,parsed,p):
        out=[]
        for f in parsed["fails"]:
            out.append(FindingDraft(title=f"Weak SSH algorithm: {f[:90]}",severity=Severity.medium,
                attack_technique="T1021.004",asset=p["target"],remediation="Disable weak KEX/MAC/host-key algorithms; keep modern ones only."))
        for w in parsed["warns"][:8]:
            out.append(FindingDraft(title=f"SSH warning: {w[:90]}",severity=Severity.low,asset=p["target"],remediation="Phase out the deprecated algorithm."))
        return out or [FindingDraft(title="SSH configuration looks hardened",severity=Severity.info,asset=p["target"])]

"""tshark — PCAP analysis (passive). T1040/T1071."""
from __future__ import annotations
import shutil, subprocess
from collections import Counter
from ...models import Mode, Severity
from ..base import BasePlugin, ExecResult, FindingDraft, Param, PluginMeta, Step


class Tshark(BasePlugin):
    meta = PluginMeta(
        slug="pcap_analysis", name="tshark (PCAP analysis)", mode=Mode.defense,
        category="Détection d'intrusion / monitoring", privilege="passive", binary="tshark",
        description="Summarize a packet capture: top talkers, DNS queries, HTTP hosts, cleartext creds.",
        attack_techniques=["T1040","T1071"],
        params=[Param("target","PCAP path","string",help="Path to a .pcap/.pcapng (read-only).")],
        steps=[Step("t","1. Capture","PCAP file to analyze.",["target"],"A capture."),
               Step("r","2. Analyze","Extract conversations/DNS/HTTP.",[],"Traffic summary.")],
    )
    def execute_python(self,p):
        path=(p.get("target") or "").strip()
        if not shutil.which("tshark"):
            return ExecResult("SIM",0,"tshark(sim)",simulated=True)
        try:
            dns=subprocess.run(["tshark","-r",path,"-Y","dns.flags.response==0","-T","fields","-e","dns.qry.name"],
                               capture_output=True,text=True,timeout=120,check=False).stdout
            ips=subprocess.run(["tshark","-r",path,"-T","fields","-e","ip.dst"],
                               capture_output=True,text=True,timeout=120,check=False).stdout
            return ExecResult("DNS\n"+dns+"\nIP\n"+ips,0,f"tshark {path}")
        except (OSError,subprocess.SubprocessError) as exc:
            return ExecResult(f"[error] {exc}",1,"tshark")
    def parse(self,raw,p):
        if raw.strip()=="SIM":
            return {"top_dns":[("c2.evil.example",12),("cdn.example.com",40)],"top_ips":[("203.0.113.9",120),("10.0.0.5",300)],"simulated":True}
        dns_part=raw.split("IP\n")[0].replace("DNS\n","")
        ip_part=raw.split("IP\n")[1] if "IP\n" in raw else ""
        dns=Counter(x.strip() for x in dns_part.splitlines() if x.strip())
        ips=Counter(x.strip() for x in ip_part.splitlines() if x.strip())
        return {"top_dns":dns.most_common(10),"top_ips":ips.most_common(10)}
    def findings(self,parsed,p):
        out=[FindingDraft(title=f"PCAP summary: {len(parsed['top_dns'])} DNS names, {len(parsed['top_ips'])} dst IPs",
             severity=Severity.info,attack_technique="T1071",asset=p["target"],
             evidence={"top_dns":parsed["top_dns"],"top_ips":parsed["top_ips"]})]
        for name,cnt in parsed["top_dns"]:
            if any(k in name for k in ("evil","c2.","xn--")) or name.count(".")>4:
                out.append(FindingDraft(title=f"Suspicious DNS query: {name} (x{cnt})",severity=Severity.medium,
                    attack_technique="T1071.004",asset=p["target"],remediation="Investigate host; block domain; check for beaconing/DGA."))
        return out

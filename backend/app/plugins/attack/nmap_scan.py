"""Guided Nmap network scan (ATTACK / Reconnaissance-Discovery).

Wraps the real ``nmap`` binary, requesting XML on stdout (``-oX -``) and
parsing it into structured host/port records. ATT&CK: T1046 (Network Service
Discovery), T1018 (Remote System Discovery).

Privilege: ACTIVE — it sends packets to the target, so the scope guard requires
an accepted, in-window authorization whose perimeter covers the target.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from ...models import Mode, Severity
from ..base import BasePlugin, ExecResult, FindingDraft, Param, PluginMeta, Step

# Services that warrant a closer look when found exposed.
_NOTABLE = {
    "21": ("ftp", Severity.medium, "Cleartext file transfer; credentials sniffable."),
    "23": ("telnet", Severity.high, "Cleartext remote administration."),
    "135": ("msrpc", Severity.medium, "Windows RPC exposed."),
    "445": ("microsoft-ds", Severity.high, "SMB exposed; common lateral-movement vector."),
    "3389": ("ms-wbt-server", Severity.medium, "RDP exposed to the network."),
    "5900": ("vnc", Severity.medium, "VNC exposed; often weakly authenticated."),
    "6379": ("redis", Severity.high, "Redis often unauthenticated by default."),
    "27017": ("mongodb", Severity.high, "MongoDB often unauthenticated by default."),
}


class NmapScan(BasePlugin):
    meta = PluginMeta(
        slug="nmap_scan",
        name="Nmap network scan",
        mode=Mode.attack,
        category="Network scan",
        privilege="active",
        description=(
            "Discover live hosts, open ports and running services on authorized "
            "targets, with optional service/version detection."
        ),
        attack_techniques=["T1046", "T1018"],
        binary="nmap",
        params=[
            Param("target", "Target", "string", required=True,
                  help="Host, IP or CIDR inside the authorized perimeter (e.g. 10.0.0.0/24)."),
            Param("profile", "Scan profile", "choice", default="top1000",
                  choices=["quick", "top1000", "full", "service"],
                  help="quick=-F (100 ports), top1000=default, full=all 65535, service=-sV."),
            Param("service_detection", "Service/version detection", "bool", required=False,
                  default=False, help="Adds -sV to fingerprint service versions."),
            Param("timing", "Timing template", "choice", default="T3",
                  choices=["T2", "T3", "T4"],
                  help="Lower is stealthier/slower; T3 is the balanced default."),
        ],
        steps=[
            Step("target", "1. Define the target",
                 "Enter the host/IP/CIDR to scan. It must fall inside the scope "
                 "authorization declared for this engagement, or the launch is blocked.",
                 params=["target"],
                 expect="A target string validated against the authorized perimeter."),
            Step("profile", "2. Choose scan breadth",
                 "Pick how many ports to probe. Wider scans take longer and are "
                 "noisier on the target network.",
                 params=["profile", "timing"],
                 expect="A scan profile and timing template."),
            Step("detection", "3. Service detection",
                 "Optionally fingerprint service versions. This is more intrusive "
                 "and more detectable, but gives version data to correlate with CVEs.",
                 params=["service_detection"],
                 expect="Whether -sV runs."),
            Step("launch", "4. Review & launch",
                 "Confirm the resolved command. On launch the scope guard re-checks "
                 "the target and the action is written to the immutable audit log "
                 "before nmap starts.",
                 params=[],
                 expect="Structured host/port results and derived findings."),
        ],
    )

    def build_argv(self, params: dict) -> list[str]:
        argv = ["nmap", "-oX", "-", f"-{params.get('timing', 'T3')}"]
        profile = params.get("profile", "top1000")
        if profile == "quick":
            argv.append("-F")
        elif profile == "full":
            argv += ["-p-"]
        elif profile == "service":
            argv.append("-sV")
        if params.get("service_detection") and "-sV" not in argv:
            argv.append("-sV")
        argv.append(params["target"])
        return argv

    def simulate(self, params: dict) -> str:
        target = params.get("target", "192.0.2.10")
        return f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="simulated">
  <host>
    <status state="up"/>
    <address addr="{target}" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/><service name="http" product="nginx" version="1.24"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/><service name="microsoft-ds"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

    def parse(self, raw_output: str, params: dict) -> dict:
        hosts: list[dict] = []
        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError:
            return {"hosts": [], "parse_error": True, "raw_head": raw_output[:500]}

        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue
            addr_el = host.find("address")
            addr = addr_el.get("addr") if addr_el is not None else ""
            ports = []
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = port.find("service")
                ports.append({
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "service": (svc.get("name") if svc is not None else "") or "",
                    "product": (svc.get("product") if svc is not None else "") or "",
                    "version": (svc.get("version") if svc is not None else "") or "",
                })
            hosts.append({"address": addr, "open_ports": ports})
        return {"hosts": hosts, "host_count": len(hosts),
                "open_port_count": sum(len(h["open_ports"]) for h in hosts)}

    def findings(self, parsed: dict, params: dict) -> list[FindingDraft]:
        drafts: list[FindingDraft] = []
        for host in parsed.get("hosts", []):
            addr = host["address"]
            for p in host["open_ports"]:
                portid = p["port"]
                notable = _NOTABLE.get(portid)
                if notable:
                    _, sev, note = notable
                    title = f"Exposed {p['service'] or notable[0]} on {addr}:{portid}"
                    desc = note
                else:
                    sev = Severity.info
                    title = f"Open port {addr}:{portid}/{p['protocol']} ({p['service'] or 'unknown'})"
                    desc = "Open service discovered during authorized scanning."
                ver = f"{p['product']} {p['version']}".strip()
                drafts.append(FindingDraft(
                    title=title, severity=sev, description=desc, asset=f"{addr}:{portid}",
                    attack_technique="T1046",
                    evidence={"service": p["service"], "version": ver or None},
                ))
        return drafts

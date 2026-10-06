"""Masscan high-speed port scan (ATTACK / Network scan, active). ATT&CK T1046."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Masscan(BasePlugin):
    meta = PluginMeta(
        slug="masscan", name="Masscan (fast port scan)", mode=Mode.attack,
        category="Network scan", privilege="active", binary="masscan",
        description="Very fast TCP port sweep across large ranges. Use a sane rate on shared networks.",
        attack_techniques=["T1046"],
        params=[
            Param("target", "Target range", "string", help="IP/CIDR inside the authorized perimeter."),
            Param("ports", "Ports", "string", required=False, default="1-1000", help="Port spec, e.g. 1-65535 or 80,443,8080."),
            Param("rate", "Packets/sec", "int", required=False, default=1000, help="Keep moderate to avoid disrupting the target."),
        ],
        steps=[
            Step("target", "1. Range", "Target range (must be in scope). Blocked otherwise.", ["target"], "A range."),
            Step("ports", "2. Ports & rate", "Port spec and packet rate. High rates are noisy and disruptive.", ["ports", "rate"], "Scan parameters."),
            Step("run", "3. Scan", "Sweep and collect open ports.", [], "Open host:port list."),
        ],
    )

    def build_argv(self, p):
        return ["masscan", p["target"], "-p", str(p.get("ports", "1-1000")),
                "--rate", str(p.get("rate", 1000)), "-oL", "-"]

    def simulate(self, p):
        return "open tcp 80 192.0.2.10 0\nopen tcp 443 192.0.2.10 0\nopen tcp 22 192.0.2.11 0\n"

    def parse(self, raw, p):
        hosts = {}
        for m in re.finditer(r"open\s+tcp\s+(\d+)\s+([\d.]+)", raw):
            hosts.setdefault(m.group(2), []).append(m.group(1))
        return {"hosts": {h: sorted(ps, key=int) for h, ps in hosts.items()},
                "open_count": sum(len(v) for v in hosts.values())}

    def findings(self, parsed, p):
        out = []
        for host, ports in parsed["hosts"].items():
            out.append(FindingDraft(title=f"{len(ports)} open port(s) on {host}", severity=Severity.info,
                                    attack_technique="T1046", asset=host, evidence={"ports": ports}))
        return out

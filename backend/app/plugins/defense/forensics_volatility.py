"""Volatility 3 memory forensics (DEFENSE / Forensics, passive)."""
from __future__ import annotations
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Volatility(BasePlugin):
    meta = PluginMeta(
        slug="volatility", name="Volatility 3 (memory forensics)", mode=Mode.defense,
        category="Analyse de malware / forensics", privilege="passive", binary="vol",
        description="Investigate a RAM dump: processes, network connections, injected code.",
        attack_techniques=["T1059"],
        params=[
            Param("dump", "Memory dump path", "string", help="Path to a RAM image on the VM (read-only)."),
            Param("plugin", "Volatility plugin", "choice", default="windows.pslist",
                  choices=["windows.pslist", "windows.netscan", "windows.malfind", "linux.pslist"],
                  help="Which Volatility analysis to run."),
        ],
        steps=[
            Step("dump", "1. Memory image", "Path to the acquired RAM dump.", ["dump"], "A dump file."),
            Step("plugin", "2. Analysis", "Pick the Volatility plugin to run.", ["plugin"], "An analysis."),
            Step("run", "3. Analyze", "Run and summarize notable artifacts.", [], "Processes/connections/injections."),
        ],
    )

    def build_argv(self, p):
        return ["vol", "-f", p["dump"], p.get("plugin", "windows.pslist")]

    def simulate(self, p):
        return ("PID\tPPID\tImageFileName\n4\t0\tSystem\n612\t4\tsmss.exe\n"
                "1337\t612\tsvch0st.exe\n")

    def parse(self, raw, p):
        lines = [l for l in raw.splitlines() if l.strip()]
        suspicious = [l for l in lines if any(s in l.lower() for s in ("svch0st", "powershell", "rundll32", "mimikatz"))]
        return {"rows": len(lines), "suspicious": suspicious, "plugin": p.get("plugin")}

    def findings(self, parsed, p):
        out = [FindingDraft(title=f"Volatility {parsed['plugin']} parsed ({parsed['rows']} rows)",
                            severity=Severity.info, evidence={"rows": parsed["rows"]})]
        for s in parsed["suspicious"]:
            out.append(FindingDraft(title=f"Suspicious artifact in memory: {s.strip()[:90]}",
                                    severity=Severity.high, attack_technique="T1059",
                                    remediation="Correlate with disk/EDR; preserve the image; escalate IR.",
                                    evidence={"row": s.strip()}))
        return out

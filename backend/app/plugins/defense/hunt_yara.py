"""YARA signature scan (DEFENSE / Malware analysis & threat hunting, passive)."""
from __future__ import annotations
import re, shutil, subprocess
from ...models import Mode, Severity
from ..base import BasePlugin, ExecResult, FindingDraft, Param, PluginMeta, Step


class Yara(BasePlugin):
    meta = PluginMeta(
        slug="yara", name="YARA (signature scan)", mode=Mode.defense,
        category="Analyse de malware / forensics", privilege="passive", binary="yara",
        description="Scan files/directories against YARA rules to hunt known malware patterns.",
        attack_techniques=["T1059"],
        params=[
            Param("rules", "Rules file path", "string", help="Path to a .yar/.yara rules file on the VM."),
            Param("target", "Path to scan", "string", help="File or directory to scan (local, read-only)."),
            Param("recursive", "Recursive", "bool", required=False, default=True, help="Scan directories recursively."),
        ],
        steps=[
            Step("rules", "1. Rules", "Path to your YARA ruleset.", ["rules"], "A rules file."),
            Step("target", "2. Target path", "File/dir to scan. Nothing is modified.", ["target", "recursive"], "A path."),
            Step("run", "3. Scan", "Match rules and list hits.", [], "Rule matches per file."),
        ],
    )

    def build_argv(self, p):
        argv = ["yara"]
        if p.get("recursive", True):
            argv.append("-r")
        argv += [p["rules"], p["target"]]
        return argv

    def simulate(self, p):
        t = p.get("target", "/tmp/sample")
        return f"Mirai_Botnet {t}/bin1\nSuspicious_PowerShell {t}/doc/invoice.lnk\n"

    def parse(self, raw, p):
        matches = []
        for line in raw.splitlines():
            m = re.match(r"^(\S+)\s+(.+)$", line.strip())
            if m:
                matches.append({"rule": m.group(1), "file": m.group(2)})
        return {"matches": matches, "count": len(matches)}

    def findings(self, parsed, p):
        if not parsed["count"]:
            return [FindingDraft(title=f"No YARA matches under {p['target']}", severity=Severity.info)]
        return [FindingDraft(title=f"YARA match: {m['rule']}", severity=Severity.high,
                             attack_technique="T1059", asset=m["file"],
                             remediation="Isolate the host, preserve the artifact, and begin IR triage.",
                             evidence=m) for m in parsed["matches"]]

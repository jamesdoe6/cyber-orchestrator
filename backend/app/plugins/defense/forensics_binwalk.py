"""Binwalk — firmware/file carving & embedded-file detection (passive). T1005."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Binwalk(BasePlugin):
    meta = PluginMeta(
        slug="binwalk", name="Binwalk (firmware/carving)", mode=Mode.defense,
        category="Analyse de malware / forensics", privilege="passive", binary="binwalk",
        description="Scan a binary/firmware image for embedded files, filesystems and signatures.",
        attack_techniques=["T1005"],
        params=[Param("target","File path","string",help="Binary/firmware image (read-only).")],
        steps=[Step("t","1. File","Image to scan.",["target"],"A file."),
               Step("r","2. Scan","Detect embedded content.",[],"Signature map.")],
    )
    def build_argv(self,p): return ["binwalk",p["target"]]
    def simulate(self,p):
        return ("DECIMAL  HEXADECIMAL  DESCRIPTION\n0        0x0  uImage header\n512      0x200  gzip compressed data\n"
                "131072   0x20000  Squashfs filesystem\n262144   0x40000  LZMA compressed data\n")
    def parse(self,raw,p):
        sigs=[l.split("  ",2)[-1].strip() for l in raw.splitlines() if re.match(r"^\d+\s",l)]
        return {"signatures":sigs,"count":len(sigs)}
    def findings(self,parsed,p):
        if not parsed["count"]:
            return [FindingDraft(title="No embedded signatures found",severity=Severity.info)]
        fs=[s for s in parsed["signatures"] if any(k in s.lower() for k in ("filesystem","squashfs","cpio","jffs","cramfs"))]
        out=[FindingDraft(title=f"{parsed['count']} embedded signature(s) found",severity=Severity.info,
             attack_technique="T1005",asset=p["target"],evidence={"signatures":parsed["signatures"][:25]})]
        if fs:
            out.append(FindingDraft(title=f"Embedded filesystem(s) detected: {', '.join(fs[:3])}",severity=Severity.low,
                asset=p["target"],remediation="Extract (binwalk -e) and review for secrets/backdoors."))
        return out

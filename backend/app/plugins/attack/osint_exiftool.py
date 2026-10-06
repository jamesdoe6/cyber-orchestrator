"""ExifTool — document/image metadata extraction (OSINT + forensics, passive). T1592."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class ExifTool(BasePlugin):
    meta = PluginMeta(
        slug="exiftool", name="ExifTool (metadata)", mode=Mode.attack,
        category="Reconnaissance / OSINT", privilege="passive", binary="exiftool",
        description="Extract metadata (author, software, GPS, usernames) from a document or image.",
        attack_techniques=["T1592","T1589"],
        params=[Param("target","File path","string",help="Path to a file collected from public sources.")],
        steps=[Step("t","1. File","File to extract metadata from (read-only).",["target"],"A file."),
               Step("r","2. Extract","Pull metadata fields.",[],"Author, software, GPS, etc.")],
    )
    def build_argv(self,p): return ["exiftool",p["target"]]
    def simulate(self,p):
        return ("Author                          : j.doe\nCreator Tool                    : Microsoft Word 2019\n"
                "GPS Position                    : 48.8566 N, 2.3522 E\nCompany                         : ACME Corp\n")
    def parse(self,raw,p):
        fields={}
        for line in raw.splitlines():
            if ":" in line:
                k,_,v=line.partition(":");fields[k.strip()]=v.strip()
        leak={k:v for k,v in fields.items() if any(s in k.lower() for s in ("author","creator","gps","company","owner","producer","user"))}
        return {"all":fields,"leak":leak}
    def findings(self,parsed,p):
        out=[FindingDraft(title=f"Metadata extracted ({len(parsed['all'])} fields) from {p['target']}",
             severity=Severity.info,attack_technique="T1592",asset=p["target"])]
        if parsed["leak"]:
            out.append(FindingDraft(title="Sensitive metadata leak (author/software/GPS/company)",
                severity=Severity.low,attack_technique="T1589",asset=p["target"],
                description="Document metadata reveals internal names/software/locations useful for targeting.",
                remediation="Strip metadata from public documents (exiftool -all=).",evidence=parsed["leak"]))
        return out

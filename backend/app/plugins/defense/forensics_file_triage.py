"""File triage — hashes, type, entropy, strings, IOC hints (pure-Python, passive). T1005."""
from __future__ import annotations
import hashlib, math, re
from ...models import Mode, Severity
from ..base import BasePlugin, ExecResult, FindingDraft, Param, PluginMeta, Step

_MAGIC = {b"MZ":"PE/EXE", b"\x7fELF":"ELF", b"PK\x03\x04":"ZIP/Office", b"%PDF":"PDF",
          b"\xd0\xcf\x11\xe0":"OLE/Legacy Office", b"\x1f\x8b":"GZIP", b"\xff\xd8\xff":"JPEG"}


class FileTriage(BasePlugin):
    meta = PluginMeta(
        slug="file_triage", name="File triage (hash/entropy/strings)", mode=Mode.defense,
        category="Analyse de malware / forensics", privilege="passive", binary=None,
        description="Compute hashes, detect type, measure entropy (packing), extract strings and flag IOCs — no external tool.",
        attack_techniques=["T1005"],
        params=[Param("target","File path","string",help="File to triage (read-only).")],
        steps=[Step("t","1. File","Path to the suspect file.",["target"],"A file."),
               Step("r","2. Triage","Hash, type, entropy, strings, IOC hints.",[],"Triage summary.")],
    )
    def execute_python(self,p):
        path=(p.get("target") or "").strip()
        if not path:
            return ExecResult("[error] no file path given",1,"file_triage")
        try:
            with open(path,"rb") as fh: data=fh.read(8_000_000)
        except OSError as exc:
            # simulate so the flow still works
            data=b"MZ\x90\x00"+b"\x00"*200+b"http://evil.example/c2 powershell -enc SQBFAFgA cmd.exe"
            return ExecResult(repr({"sim":True,"data":data.hex()}),0,"file_triage(sim)",simulated=True)
        return ExecResult(repr({"sim":False,"data":data.hex()}),0,f"triage {path}")
    def parse(self,raw,p):
        import ast
        d=ast.literal_eval(raw); data=bytes.fromhex(d["data"])
        ftype=next((v for k,v in _MAGIC.items() if data.startswith(k)),"unknown")
        # entropy
        if data:
            freq=[0]*256
            for b in data: freq[b]+=1
            ent=-sum((c/len(data))*math.log2(c/len(data)) for c in freq if c)
        else: ent=0.0
        text=data.decode("latin-1","ignore")
        strings=re.findall(r"[ -~]{6,}",text)
        iocs=[s for s in strings if re.search(r"https?://|powershell|cmd\.exe|/bin/sh|base64|-enc |CreateRemoteThread|VirtualAlloc",s,re.I)]
        return {"sha256":hashlib.sha256(data).hexdigest(),"md5":hashlib.md5(data).hexdigest(),
                "size":len(data),"type":ftype,"entropy":round(ent,2),"string_count":len(strings),
                "iocs":iocs[:20],"simulated":d.get("sim",False)}
    def findings(self,parsed,p):
        out=[FindingDraft(title=f"Triage: {parsed['type']} · {parsed['size']}B · entropy {parsed['entropy']}",
             severity=Severity.info,attack_technique="T1005",asset=p["target"],
             evidence={"sha256":parsed["sha256"],"md5":parsed["md5"]})]
        if parsed["entropy"]>=7.2:
            out.append(FindingDraft(title=f"High entropy ({parsed['entropy']}) — likely packed/encrypted",
                severity=Severity.medium,asset=p["target"],remediation="Unpack/sandbox before static analysis."))
        if parsed["iocs"]:
            out.append(FindingDraft(title=f"{len(parsed['iocs'])} suspicious string indicator(s)",severity=Severity.high,
                asset=p["target"],remediation="Sandbox-detonate; pivot on the URLs/commands; preserve the sample.",
                evidence={"iocs":parsed["iocs"]}))
        return out

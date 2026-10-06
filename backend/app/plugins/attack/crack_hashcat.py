"""Hashcat GPU hash cracking (ATTACK / Cracking, offensive). ATT&CK T1110.002."""
from __future__ import annotations
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Hashcat(BasePlugin):
    meta = PluginMeta(
        slug="hashcat", name="Hashcat (GPU cracking)", mode=Mode.attack,
        category="Brute force / cracking", privilege="offensive", binary="hashcat",
        description="GPU-accelerated cracking of hashes / WPA handshakes captured in-scope.",
        attack_techniques=["T1110.002"],
        params=[
            Param("hashfile", "Hash/handshake file", "string", help="Path to hashes or a converted WPA (.hc22000) file."),
            Param("mode", "Hash mode (-m)", "int", default=0, help="e.g. 0=MD5, 1800=sha512crypt, 22000=WPA."),
            Param("wordlist", "Wordlist path", "string", help="Path to a wordlist on the VM."),
        ],
        steps=[
            Step("input", "1. Hashes & mode", "Captured hashes/handshake and the matching -m mode.", ["hashfile", "mode"], "Hash input."),
            Step("wl", "2. Wordlist", "Wordlist for the dictionary attack.", ["wordlist"], "A wordlist."),
            Step("run", "3. Crack", "Run and report recovered values.", [], "Recovered plaintext."),
        ],
    )

    def build_argv(self, p):
        return ["hashcat", "-m", str(p.get("mode", 0)), "-a", "0", "--potfile-disable",
                "--quiet", "-o", "/dev/stdout", p["hashfile"], p["wordlist"]]

    def simulate(self, p):
        return "8a9f...:CorrectHorse1\n"

    def parse(self, raw, p):
        rec = [l for l in raw.splitlines() if ":" in l and not l.lower().startswith(("session", "status"))]
        return {"recovered": rec, "count": len(rec)}

    def findings(self, parsed, p):
        if not parsed["count"]:
            return [FindingDraft(title="No values recovered", severity=Severity.info, attack_technique="T1110.002")]
        return [FindingDraft(title=f"{parsed['count']} value(s) recovered by hashcat", severity=Severity.high,
                             attack_technique="T1110.002", remediation="Stronger passphrases; WPA3; slow hashing.",
                             evidence={"sample": [r.split(':')[-1] for r in parsed['recovered'][:10]]})]

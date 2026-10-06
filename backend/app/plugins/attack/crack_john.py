"""John the Ripper hash cracking (ATTACK / Cracking, offensive). ATT&CK T1110.002."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class John(BasePlugin):
    meta = PluginMeta(
        slug="john", name="John the Ripper (hashes)", mode=Mode.attack,
        category="Brute force / cracking", privilege="offensive", binary="john",
        description="Crack password hashes captured during an authorized engagement.",
        attack_techniques=["T1110.002"],
        params=[
            Param("hashfile", "Hash file path", "string", help="Path to a file of hashes on the VM."),
            Param("format", "Hash format", "string", required=False, default="", help="--format (e.g. sha512crypt, NT). Blank = auto."),
            Param("wordlist", "Wordlist path", "string", required=False, default="", help="--wordlist; blank = incremental."),
        ],
        steps=[
            Step("input", "1. Hashes", "Path to hashes you captured legitimately in scope.", ["hashfile", "format"], "A hash file."),
            Step("mode", "2. Attack mode", "Wordlist (fast) or incremental (slower).", ["wordlist"], "Mode."),
            Step("run", "3. Crack", "Run and report cracked hashes.", [], "Cracked plaintext count."),
        ],
    )

    def build_argv(self, p):
        argv = ["john"]
        if p.get("format"):
            argv.append(f"--format={p['format']}")
        if p.get("wordlist"):
            argv.append(f"--wordlist={p['wordlist']}")
        argv += [p["hashfile"], "--pot=/dev/stdout"]
        return argv

    def simulate(self, p):
        return "Summer2024!:$6$abcd$...\npassword1:$6$efgh$...\n2 password hashes cracked\n"

    def parse(self, raw, p):
        cracked = re.findall(r"^([^:\n]+):\$", raw, re.M)
        return {"cracked": cracked, "count": len(cracked)}

    def findings(self, parsed, p):
        if not parsed["count"]:
            return [FindingDraft(title="No hashes cracked", severity=Severity.info, attack_technique="T1110.002")]
        return [FindingDraft(title=f"{parsed['count']} password hash(es) cracked", severity=Severity.high,
                             attack_technique="T1110.002", description="Weak passwords recoverable offline.",
                             remediation="Increase password length/complexity; use slow hashing (bcrypt/argon2); rotate.",
                             evidence={"sample": parsed["cracked"][:10]})]

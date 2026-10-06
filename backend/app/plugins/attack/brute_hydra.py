"""Hydra network-service brute force (ATTACK / Brute force, offensive). ATT&CK T1110.001."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Hydra(BasePlugin):
    meta = PluginMeta(
        slug="hydra", name="Hydra (credential testing)", mode=Mode.attack,
        category="Brute force / cracking", privilege="offensive", binary="hydra",
        description="Test authentication strength of a network service with a wordlist, on authorized targets.",
        attack_techniques=["T1110.001"],
        params=[
            Param("target", "Target host", "string", help="Host/IP in scope."),
            Param("service", "Service", "choice", default="ssh",
                  choices=["ssh", "ftp", "rdp", "smb", "http-get", "http-post-form"], help="Protocol module."),
            Param("username", "Username / -L file", "string", help="Single user, or a path for a user list."),
            Param("wordlist", "Password list path", "string", help="Path to a password wordlist on the VM."),
            Param("tasks", "Parallel tasks", "int", required=False, default=4, help="-t; keep modest to avoid lockouts/DoS."),
        ],
        steps=[
            Step("target", "1. Target & service", "Authorized host and the service to test. Out-of-scope is blocked.", ["target", "service"], "Host+service."),
            Step("creds", "2. Credentials source", "User (or -L list path) and the password wordlist path.", ["username", "wordlist", "tasks"], "Wordlist config."),
            Step("run", "3. Test", "Run and report any accepted credentials. Mind account-lockout policy.", [], "Valid credential pairs, if any."),
        ],
    )

    def build_argv(self, p):
        user = p["username"]
        uflag = ["-L", user] if "/" in user else ["-l", user]
        return ["hydra", *uflag, "-P", p["wordlist"], "-t", str(p.get("tasks", 4)),
                "-f", "-o", "/dev/stdout", p["target"], p.get("service", "ssh")]

    def simulate(self, p):
        return (f"[22][ssh] host: {p.get('target','192.0.2.10')}   login: admin   password: Summer2024!\n"
                "1 of 1 target successfully completed, 1 valid password found\n")

    def parse(self, raw, p):
        creds = re.findall(r"login:\s*(\S+)\s+password:\s*(\S+)", raw)
        return {"credentials": [{"user": u, "password": pw} for u, pw in creds], "count": len(creds)}

    def findings(self, parsed, p):
        if not parsed["count"]:
            return [FindingDraft(title=f"No weak credentials found on {p['target']} ({p['service']})",
                                 severity=Severity.info, attack_technique="T1110.001", asset=p["target"])]
        return [FindingDraft(title=f"Weak credential accepted on {p['target']} ({p['service']})",
                             severity=Severity.critical, attack_technique="T1110.001", asset=p["target"], cvss=9.1,
                             description=f"{parsed['count']} valid pair(s) found by dictionary attack.",
                             remediation="Enforce strong unique passwords, MFA, and lockout/rate-limiting.",
                             evidence={"accounts": [c["user"] for c in parsed["credentials"]]})]

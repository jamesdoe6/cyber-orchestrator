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
            Param("username", "Username or users-file", "string",
                  help="A single username (e.g. admin) OR an absolute path to a user list "
                       "(e.g. /home/you/users.txt). Do NOT type -l/-L — it is added automatically.",
                  suggestions=["admin", "root"]),
            Param("wordlist", "Password list (absolute path)", "string",
                  help="Absolute path to a password wordlist that exists on this machine (WSL).",
                  suggestions=["/usr/share/wordlists/rockyou.txt",
                               "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt"]),
            Param("tasks", "Parallel tasks", "int", required=False, default=4, help="-t; keep modest to avoid lockouts/DoS."),
        ],
        steps=[
            Step("target", "1. Target & service", "Authorized host and the service to test. Out-of-scope is blocked.", ["target", "service"], "Host+service."),
            Step("creds", "2. Credentials source", "A username (or a users-file path) and the password wordlist path on this machine.", ["username", "wordlist", "tasks"], "Wordlist config."),
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

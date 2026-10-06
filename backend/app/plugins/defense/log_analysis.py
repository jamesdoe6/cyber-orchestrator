"""Authentication log analysis (DEFENSE / Log analysis & threat hunting).

A pure-Python module (no external binary): it parses Linux ``sshd`` auth logs
for brute-force and suspicious-success patterns. ATT&CK coverage: T1110.001
(Password Guessing) and T1078 (Valid Accounts).

Privilege: PASSIVE — it only reads logs the operator supplies, so it runs
without a target authorization, but is still audited.
"""
from __future__ import annotations

import re
from collections import defaultdict

from ...models import Mode, Severity
from ..base import BasePlugin, ExecResult, FindingDraft, Param, PluginMeta, Step

_FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
_ACCEPT = re.compile(r"Accepted \w+ for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")

_SAMPLE = """\
Oct  6 10:00:01 host sshd[1001]: Failed password for invalid user admin from 203.0.113.9 port 51000 ssh2
Oct  6 10:00:03 host sshd[1002]: Failed password for invalid user admin from 203.0.113.9 port 51002 ssh2
Oct  6 10:00:05 host sshd[1003]: Failed password for root from 203.0.113.9 port 51004 ssh2
Oct  6 10:00:07 host sshd[1004]: Failed password for root from 203.0.113.9 port 51006 ssh2
Oct  6 10:00:09 host sshd[1005]: Failed password for root from 203.0.113.9 port 51008 ssh2
Oct  6 10:00:11 host sshd[1006]: Failed password for root from 203.0.113.9 port 51010 ssh2
Oct  6 10:00:13 host sshd[1007]: Accepted password for root from 203.0.113.9 port 51012 ssh2
Oct  6 10:05:00 host sshd[1100]: Accepted publickey for deploy from 198.51.100.4 port 4000 ssh2
"""


class LogAnalysis(BasePlugin):
    meta = PluginMeta(
        slug="log_analysis",
        name="Auth log analysis",
        mode=Mode.defense,
        category="Log analysis",
        privilege="passive",
        description=(
            "Parse sshd authentication logs for brute-force bursts and "
            "suspicious successful logins, with prioritized remediation."
        ),
        attack_techniques=["T1110.001", "T1078"],
        binary=None,
        params=[
            Param("log_text", "Log content", "textarea", required=False, default="",
                  help="Paste sshd/auth.log lines. Leave empty with no path to run on sample data."),
            Param("log_path", "Log file path", "string", required=False, default="",
                  help="Optional path on the VM, e.g. /var/log/auth.log (read-only)."),
            Param("bruteforce_threshold", "Brute-force threshold", "int", required=False, default=5,
                  help="Failed attempts from one source IP before it is flagged."),
        ],
        steps=[
            Step("source", "1. Provide the log source",
                 "Paste log lines or give a readable path on the VM. The analyzer "
                 "never modifies the source; it reads only.",
                 params=["log_text", "log_path"],
                 expect="A body of sshd log lines to analyze."),
            Step("rules", "2. Tune detections",
                 "Set how many failures from a single IP constitute a brute-force "
                 "attempt. Lower values are more sensitive.",
                 params=["bruteforce_threshold"],
                 expect="A configured threshold."),
            Step("analyze", "3. Analyze",
                 "Run the detections. The analysis itself is recorded in the audit "
                 "log. No packets touch any target — this is passive.",
                 params=[],
                 expect="Per-IP statistics and prioritized findings with remediation."),
        ],
    )

    def execute_python(self, params: dict) -> ExecResult:
        text = (params.get("log_text") or "").strip()
        path = (params.get("log_path") or "").strip()
        simulated = False
        if not text and path:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError as exc:
                return ExecResult(raw_output=f"[error] cannot read {path}: {exc}",
                                  exit_code=1, command=f"read {path}")
        if not text:
            text = _SAMPLE
            simulated = True
        return ExecResult(raw_output=text, exit_code=0,
                          command="python:log_analysis", simulated=simulated)

    def parse(self, raw_output: str, params: dict) -> dict:
        failed: dict[str, int] = defaultdict(int)
        failed_users: dict[str, set] = defaultdict(set)
        accepted: list[dict] = []
        for line in raw_output.splitlines():
            m = _FAILED.search(line)
            if m:
                failed[m.group("ip")] += 1
                failed_users[m.group("ip")].add(m.group("user"))
                continue
            m = _ACCEPT.search(line)
            if m:
                accepted.append({"user": m.group("user"), "ip": m.group("ip")})
        return {
            "failed_by_ip": dict(failed),
            "failed_users_by_ip": {k: sorted(v) for k, v in failed_users.items()},
            "accepted": accepted,
            "total_failed": sum(failed.values()),
            "total_accepted": len(accepted),
        }

    def findings(self, parsed: dict, params: dict) -> list[FindingDraft]:
        threshold = int(params.get("bruteforce_threshold", 5) or 5)
        drafts: list[FindingDraft] = []
        accepted_ips = {a["ip"] for a in parsed.get("accepted", [])}

        for ip, count in parsed.get("failed_by_ip", {}).items():
            if count < threshold:
                continue
            success_after = ip in accepted_ips
            sev = Severity.critical if success_after else Severity.high
            users = parsed["failed_users_by_ip"].get(ip, [])
            desc = (f"{count} failed SSH logins from {ip} targeting user(s): "
                    f"{', '.join(users[:8])}.")
            if success_after:
                desc += " A successful login from the same IP followed — treat as a likely compromise."
            drafts.append(FindingDraft(
                title=f"SSH brute-force from {ip}" + (" with successful login" if success_after else ""),
                severity=sev, description=desc, asset=ip,
                attack_technique="T1078" if success_after else "T1110.001",
                remediation=(
                    "Block the source IP at the firewall; enforce key-only SSH "
                    "(PasswordAuthentication no); deploy fail2ban/rate-limiting; "
                    + ("ROTATE credentials and investigate the host for the "
                       "successful session — possible account takeover." if success_after
                       else "alert on repeated auth failures in the SIEM.")
                ),
                evidence={"failed_attempts": count, "users": users, "successful_login": success_after},
            ))
        return drafts

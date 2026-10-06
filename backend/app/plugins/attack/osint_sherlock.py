"""Sherlock username search across social networks (ATTACK / Recon, passive). ATT&CK T1593.001."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Sherlock(BasePlugin):
    meta = PluginMeta(
        slug="sherlock", name="Sherlock (usernames)", mode=Mode.attack,
        category="Reconnaissance / OSINT", privilege="passive", binary="sherlock",
        description="Find a username across many social platforms (public profiles).",
        attack_techniques=["T1593.001"],
        params=[Param("target", "Username", "string", help="Username/pseudonym to search for.")],
        steps=[
            Step("target", "1. Username", "Enter the username to look up on public platforms.", ["target"], "A username."),
            Step("run", "2. Search", "Query platforms and list accounts found.", [], "List of profile URLs."),
        ],
    )

    def build_argv(self, p):
        return ["sherlock", "--print-found", "--no-color", p["target"]]

    def simulate(self, p):
        u = p.get("target", "jdoe")
        return "\n".join([f"[+] GitHub: https://github.com/{u}",
                          f"[+] Twitter: https://twitter.com/{u}",
                          f"[+] Reddit: https://reddit.com/user/{u}"])

    def parse(self, raw, p):
        urls = re.findall(r"https?://\S+", raw)
        return {"profiles": urls, "count": len(urls)}

    def findings(self, parsed, p):
        if not parsed["count"]:
            return []
        return [FindingDraft(title=f"{parsed['count']} public profile(s) for '{p['target']}'",
                             severity=Severity.info, attack_technique="T1593.001", asset=p["target"],
                             evidence={"profiles": parsed["profiles"][:40]})]

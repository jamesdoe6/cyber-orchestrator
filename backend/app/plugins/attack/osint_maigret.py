"""Maigret — deep username OSINT across 2500+ sites (passive). T1593.001."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Maigret(BasePlugin):
    meta = PluginMeta(
        slug="maigret", name="Maigret (username OSINT)", mode=Mode.attack,
        category="Reconnaissance / OSINT", privilege="passive", binary="maigret",
        description="Find accounts for a username across 2500+ sites (deeper than Sherlock).",
        attack_techniques=["T1593.001","T1589"],
        params=[Param("target","Username","string",help="Username/pseudonym to search.")],
        steps=[Step("t","1. Username","Username to look up.",["target"],"A username."),
               Step("r","2. Search","Query sites and list found accounts.",[],"Profile URLs.")],
    )
    def build_argv(self,p): return ["maigret",p["target"],"--no-color","--no-progressbar"]
    def simulate(self,p):
        u=p.get("target","jdoe")
        return "\n".join([f"[+] GitHub: https://github.com/{u}",f"[+] GitLab: https://gitlab.com/{u}",
                          f"[+] Keybase: https://keybase.io/{u}",f"[+] HackerNews: https://news.ycombinator.com/user?id={u}"])
    def parse(self,raw,p):
        urls=re.findall(r"https?://\S+",raw);return {"profiles":urls,"count":len(urls)}
    def findings(self,parsed,p):
        if not parsed["count"]: return []
        return [FindingDraft(title=f"{parsed['count']} account(s) found for '{p['target']}'",severity=Severity.info,
                attack_technique="T1593.001",asset=p["target"],evidence={"profiles":parsed["profiles"][:60]})]

"""SQLmap SQL-injection testing (ATTACK / Web app pentest, offensive). ATT&CK T1190."""
from __future__ import annotations
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Sqlmap(BasePlugin):
    meta = PluginMeta(
        slug="sqlmap", name="SQLmap (SQLi)", mode=Mode.attack,
        category="Web app pentest", privilege="offensive", binary="sqlmap",
        description="Detect and characterize SQL injection on an authorized URL. Enumeration only by default.",
        attack_techniques=["T1190"],
        params=[
            Param("target", "Target URL", "string", help="URL with parameter, e.g. https://app.example.com/item?id=1 (in scope)."),
            Param("level", "Level", "int", required=False, default=1, help="sqlmap --level (1-5)."),
            Param("risk", "Risk", "int", required=False, default=1, help="sqlmap --risk (1-3). Keep low."),
        ],
        steps=[
            Step("target", "1. Target URL", "Authorized URL with an injectable parameter. Out-of-scope is blocked.", ["target"], "A URL."),
            Step("tuning", "2. Level & risk", "Higher level/risk = deeper but more intrusive. Keep risk low unless authorized.", ["level", "risk"], "Tuning."),
            Step("run", "3. Test", "Run detection (--batch, no data dump by default).", [], "Injection verdict per parameter."),
        ],
    )

    def build_argv(self, p):
        return ["sqlmap", "-u", p["target"], "--batch", f"--level={p.get('level',1)}",
                f"--risk={p.get('risk',1)}", "--answers=quit=N"]

    def simulate(self, p):
        return ("Parameter: id (GET)\n    Type: boolean-based blind\n"
                "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
                "back-end DBMS: MySQL >= 5.0\n")

    def parse(self, raw, p):
        injectable = "is vulnerable" in raw.lower() or "Type:" in raw
        import re
        dbms = (re.search(r"back-end DBMS:\s*(.+)", raw) or [None, ""])[1].strip() if injectable else ""
        types = re.findall(r"Type:\s*(.+)", raw)
        return {"injectable": injectable, "dbms": dbms, "types": [t.strip() for t in types]}

    def findings(self, parsed, p):
        if not parsed["injectable"]:
            return [FindingDraft(title=f"No SQL injection confirmed on {p['target']}", severity=Severity.info,
                                 attack_technique="T1190", asset=p["target"])]
        return [FindingDraft(title=f"SQL injection confirmed on {p['target']}", severity=Severity.critical,
                             attack_technique="T1190", asset=p["target"], cvss=9.8,
                             description=f"Injectable parameter; DBMS {parsed['dbms']}. Types: {', '.join(parsed['types'])}.",
                             evidence={"dbms": parsed["dbms"], "types": parsed["types"]})]

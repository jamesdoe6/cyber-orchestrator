"""WhatWeb technology fingerprinting (ATTACK / Web app pentest, active). ATT&CK T1595."""
from __future__ import annotations
import json
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class WhatWeb(BasePlugin):
    meta = PluginMeta(
        slug="whatweb", name="WhatWeb (tech fingerprint)", mode=Mode.attack,
        category="Web app pentest", privilege="active", binary="whatweb",
        description="Identify technologies, CMS, frameworks and server software of a web app.",
        attack_techniques=["T1595"],
        params=[Param("target", "Target URL", "string", help="e.g. https://app.example.com (in scope).")],
        steps=[
            Step("target", "1. Target", "Web app URL (in scope).", ["target"], "A URL."),
            Step("run", "2. Fingerprint", "Detect the stack.", [], "Technologies in use."),
        ],
    )

    def build_argv(self, p):
        return ["whatweb", "--log-json=-", "--no-errors", p["target"]]

    def simulate(self, p):
        return json.dumps([{"target": p.get("target", "https://app.example.com"),
                            "plugins": {"nginx": {"version": ["1.24.0"]}, "jQuery": {"version": ["1.8.3"]},
                                        "WordPress": {"version": ["5.2"]}}}])

    def parse(self, raw, p):
        techs = {}
        try:
            for entry in json.loads(raw[raw.index("["):raw.rindex("]") + 1]):
                for name, data in (entry.get("plugins") or {}).items():
                    ver = (data.get("version") or [None])[0]
                    techs[name] = ver
        except (ValueError, json.JSONDecodeError):
            pass
        return {"technologies": techs}

    def findings(self, parsed, p):
        out = [FindingDraft(title=f"Technology stack identified ({len(parsed['technologies'])} component(s))",
                            severity=Severity.info, attack_technique="T1595", asset=p["target"],
                            evidence=parsed["technologies"])]
        # Flag conspicuously old components as worth a CVE check.
        for name, ver in parsed["technologies"].items():
            if ver and any(name.lower() == n for n in ("wordpress", "jquery", "apache", "openssl")):
                out.append(FindingDraft(title=f"{name} {ver} in use — verify against known CVEs",
                                        severity=Severity.low, attack_technique="T1595", asset=p["target"],
                                        evidence={"component": name, "version": ver}))
        return out

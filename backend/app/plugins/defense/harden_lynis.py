"""Lynis system hardening audit (DEFENSE / Hardening, passive)."""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Lynis(BasePlugin):
    meta = PluginMeta(
        slug="lynis", name="Lynis (hardening audit)", mode=Mode.defense,
        category="Durcissement (hardening)", privilege="passive", binary="lynis",
        description="Audit local Linux host hardening; produces a hardening index and suggestions.",
        attack_techniques=["T1078"],
        params=[Param("profile", "Audit profile", "choice", required=False, default="system",
                      choices=["system"], help="Local system audit.")],
        steps=[
            Step("scope", "1. Scope", "Audits the LOCAL host configuration (read-only).", ["profile"], "Local audit."),
            Step("run", "2. Audit", "Run Lynis and parse warnings/suggestions + hardening index.", [], "Index + remediation items."),
        ],
    )

    def build_argv(self, p):
        return ["lynis", "audit", "system", "--quiet", "--no-colors"]

    def simulate(self, p):
        return ("Hardening index : 64 [#############       ]\n"
                "! SSH root login is permitted [SSH-7412]\n"
                "* Consider enabling auditd [ACCT-9628]\n"
                "* Set a password on GRUB bootloader [BOOT-5122]\n")

    def parse(self, raw, p):
        idx = re.search(r"Hardening index\s*:\s*(\d+)", raw)
        warnings = re.findall(r"^!\s*(.+)$", raw, re.M)
        suggestions = re.findall(r"^\*\s*(.+)$", raw, re.M)
        return {"hardening_index": int(idx.group(1)) if idx else None,
                "warnings": warnings, "suggestions": suggestions}

    def findings(self, parsed, p):
        out = []
        idx = parsed["hardening_index"]
        if idx is not None:
            sev = Severity.high if idx < 50 else Severity.medium if idx < 75 else Severity.low
            out.append(FindingDraft(title=f"Host hardening index: {idx}/100", severity=sev,
                                    remediation="Raise the index by applying the warnings/suggestions below.",
                                    evidence={"index": idx}))
        for w in parsed["warnings"]:
            out.append(FindingDraft(title=f"Hardening warning: {w[:110]}", severity=Severity.medium,
                                    remediation="Address this Lynis warning.", evidence={"control": w}))
        for s in parsed["suggestions"][:10]:
            out.append(FindingDraft(title=f"Hardening suggestion: {s[:110]}", severity=Severity.low,
                                    remediation=s))
        return out

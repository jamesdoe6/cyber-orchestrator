"""Wifite — aircrack-ng suite automation (ATTACK / Wifi, offensive, host).

ATT&CK T1110.002. Requires a wireless interface in MONITOR mode with injection
support on the HOST (not a container). NOTE: this does NOT work under WSL2 —
WSL2 has no direct access to the Wi-Fi radio. Use bare-metal Linux or a VM with
a USB Wi-Fi adapter passed through (and monitor-mode capable).
"""
from __future__ import annotations
import re
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step


class Wifite(BasePlugin):
    meta = PluginMeta(
        slug="wifite", name="Wifite (wifi audit)", mode=Mode.attack,
        category="Wifi (crack / injection / rogue AP)", privilege="offensive", binary="wifite",
        description="Automate handshake capture and WPA/WPA2 auditing for your OWN/authorized SSIDs. "
                    "Needs monitor mode on the host — NOT available under WSL2.",
        attack_techniques=["T1110.002", "T1557"],
        params=[
            Param("target", "Authorized SSID", "string", help="SSID you are authorized to test (must be in scope)."),
            Param("interface", "Monitor interface", "string", required=False, default="wlan0mon",
                  help="Interface already in monitor mode (airmon-ng start wlan0)."),
            Param("wordlist", "Wordlist path", "string", required=False, default="/usr/share/wordlists/rockyou.txt",
                  help="Dictionary for WPA handshake cracking."),
        ],
        steps=[
            Step("target", "1. Authorized SSID", "The SSID must be listed as an authorized target of type 'ssid'. Otherwise blocked.", ["target"], "An SSID."),
            Step("iface", "2. Interface & wordlist", "Monitor-mode interface and wordlist. (WSL2 cannot do monitor mode — use real hardware.)", ["interface", "wordlist"], "Radio config."),
            Step("run", "3. Capture & test", "Capture handshake and attempt dictionary crack.", [], "Handshake status / recovered key."),
        ],
    )

    def build_argv(self, p):
        return ["wifite", "-i", p.get("interface", "wlan0mon"), "--essid", p["target"],
                "--dict", p.get("wordlist", "/usr/share/wordlists/rockyou.txt"),
                "--kill", "--no-wps", "--crack"]

    def simulate(self, p):
        return (f"[+] scanning for target {p.get('target','MyLab-AP')}\n"
                f"[+] captured handshake for {p.get('target','MyLab-AP')}\n"
                "[+] cracked WPA key: CorrectHorseBatteryStaple\n")

    def parse(self, raw, p):
        key = (re.search(r"cracked WPA key:\s*(.+)", raw) or [None, ""])[1].strip()
        return {"handshake": "captured handshake" in raw, "key": key or None}

    def findings(self, parsed, p):
        if parsed.get("key"):
            return [FindingDraft(title=f"WPA passphrase recovered for SSID '{p['target']}'", severity=Severity.critical,
                                 attack_technique="T1110.002", asset=p["target"], cvss=8.1,
                                 remediation="Use a long random WPA2/WPA3 passphrase; prefer WPA3-SAE; segment guest SSIDs.",
                                 evidence={"handshake": True})]
        if parsed.get("handshake"):
            return [FindingDraft(title=f"WPA handshake captured for '{p['target']}' (not cracked)", severity=Severity.medium,
                                 attack_technique="T1110.002", asset=p["target"])]
        return [FindingDraft(title=f"No handshake captured for '{p['target']}'", severity=Severity.info,
                             attack_technique="T1110.002", asset=p["target"])]

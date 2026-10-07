"""Tooling inventory: which wrapped CLI tools are installed vs missing."""
from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter

from ..plugins import registry
from ..plugins.base import ToolRunner

router = APIRouter(prefix="/api/tools", tags=["tools"])

# Best-effort install hints (Debian/Kali/Ubuntu). "sim" modules work without these.
_HINTS: dict[str, str] = {
    "nmap": "sudo apt install -y nmap",
    "masscan": "sudo apt install -y masscan",
    "enum4linux-ng": "pipx install enum4linux-ng",
    "theHarvester": "pipx install theHarvester",
    "amass": "sudo apt install -y amass  # or upstream release",
    "sherlock": "pipx install sherlock-project",
    "maigret": "pipx install maigret",
    "holehe": "pipx install holehe",
    "phoneinfoga": "see github.com/sundowndev/phoneinfoga (binary release)",
    "dig": "sudo apt install -y dnsutils",
    "whois": "sudo apt install -y whois",
    "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
    "exiftool": "sudo apt install -y libimage-exiftool-perl",
    "nuclei": "upstream release (provisioning installs it)",
    "nikto": "sudo apt install -y nikto",
    "httpx": "upstream release: projectdiscovery/httpx",
    "wafw00f": "pipx install wafw00f",
    "whatweb": "sudo apt install -y whatweb",
    "ffuf": "sudo apt install -y ffuf  # or go install",
    "wpscan": "sudo gem install wpscan",
    "sslscan": "sudo apt install -y sslscan",
    "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
    "sqlmap": "sudo apt install -y sqlmap",
    "hydra": "sudo apt install -y hydra",
    "john": "sudo apt install -y john",
    "hashcat": "sudo apt install -y hashcat",
    "kerbrute": "upstream release: ropnop/kerbrute",
    "nxc": "pipx install netexec",
    "searchsploit": "sudo apt install -y exploitdb",
    "msfconsole": "see metasploit installer / Docker image",
    "wifite": "sudo apt install -y wifite aircrack-ng",
    "lynis": "sudo apt install -y lynis",
    "ssh-audit": "pipx install ssh-audit",
    "yara": "sudo apt install -y yara",
    "vol": "pipx install volatility3",
    "binwalk": "sudo apt install -y binwalk",
    "olevba": "pipx install oletools",
    "tshark": "sudo apt install -y tshark",
    "clamscan": "sudo apt install -y clamav",
    "chkrootkit": "sudo apt install -y chkrootkit",
    "trivy": "see aquasecurity/trivy install docs",
    "gitleaks": "go install github.com/gitleaks/gitleaks/v8@latest",
    "osqueryi": "see osquery.io downloads",
    "bash": "coreutils (already present)",
}


@router.get("")
def tool_inventory():
    by_binary: dict[str, set] = defaultdict(set)
    resolvers: dict[str, list] = defaultdict(list)
    pure_python = 0
    for p in registry.all_plugins():
        if p.meta.binary is None:
            pure_python += 1
            continue
        by_binary[p.meta.binary].add(p.meta.slug)
        resolvers[p.meta.binary].append(p)

    tools = []
    for binary in sorted(by_binary):
        installed = any(pl.resolve_binary() for pl in resolvers[binary]) or ToolRunner.available(binary)
        tools.append({
            "binary": binary,
            "installed": installed,
            "plugins": sorted(by_binary[binary]),
            "count": len(by_binary[binary]),
            "install_hint": _HINTS.get(binary, f"install '{binary}' from your distro/upstream"),
        })
    installed_n = sum(1 for t in tools if t["installed"])
    return {
        "tools": tools,
        "summary": {
            "total_tools": len(tools),
            "installed": installed_n,
            "missing": len(tools) - installed_n,
            "pure_python_modules": pure_python,
        },
    }

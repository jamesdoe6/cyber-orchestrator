# Tool integration catalog

Reference for the ecosystem this platform orchestrates. **Almost everything
below is mature open source — the platform wraps it, it does not reimplement
it.** Each tool becomes a `BasePlugin` with a standard interface (params,
wizard steps, ATT&CK mapping, privilege level, parser → findings).

Integration modes:
- **CLI wrapper** — `subprocess` with structured parsing (XML/JSON/regex).
- **Container** — Docker container inside the VM (isolation + independent updates).
- **Host (raw)** — direct interface access on the VM (wifi monitor/injection, LLMNR).
- **External API** — operator-supplied key; outbound call (Shodan, Censys, NVD).

Status legend: ✅ shipped example · ⬚ planned (interface ready, driver to add).

## OSINT / Reconnaissance
| Tool | Role | ATT&CK | Integration | Status |
|------|------|--------|-------------|--------|
| theHarvester | Emails/subdomains/hosts | T1596, T1593 | CLI wrapper | ⬚ |
| SpiderFoot | 300+ module OSINT automation | T1590–T1596 | CLI / local API | ⬚ |
| Amass | Subdomain enumeration | T1590.002 | CLI wrapper | ⬚ |
| recon-ng | Modular recon framework | T1595 | CLI wrapper | ⬚ |
| Sherlock / Maigret | Username search | T1593.001 | CLI wrapper | ⬚ |
| Shodan / Censys | Exposed-host search | T1596.005 | External API | ⬚ |
| Maltego CE | Relationship mapping | T1591, T1589 | Local API / link-out | ⬚ |

## Network & vulnerability scanning
| Tool | Role | ATT&CK | Integration | Status |
|------|------|--------|-------------|--------|
| **Nmap (+NSE)** | Ports/services/OS | T1046, T1018 | CLI wrapper (XML) | ✅ `nmap_scan` |
| Masscan | Internet-scale port scan | T1046 | CLI wrapper | ⬚ |
| OpenVAS / Greenbone | Full vuln scanner | Vulnerability scan | Container | ⬚ |
| Nikto | Web server vuln scan | T1595.002 | CLI wrapper | ⬚ |
| Nuclei | Template-based scanning | T1595 | CLI wrapper (JSON) | ⬚ |

## Exploitation & post-exploitation
| Tool | Role | ATT&CK | Integration | Status |
|------|------|--------|-------------|--------|
| Metasploit | Exploits/payloads/post-ex | multi-tactic | Container + RPC | ⬚ |
| SQLmap | SQL injection | T1190 | CLI wrapper | ⬚ |
| BloodHound+SharpHound | AD attack paths | T1482, T1021 | Container (Neo4j) | ⬚ |
| Responder | LLMNR/NBT-NS poisoning | T1557.001 | Host (raw) | ⬚ |
| C2 frameworks | post-ex command & control | Command & Control | Container (isolated) | ⬚ |

## Wifi
| Tool | Role | ATT&CK | Integration | Status |
|------|------|--------|-------------|--------|
| Aircrack-ng suite | Handshake capture / crack | T1110.002 | Host (monitor mode) | ⬚ |
| Wifite | Aircrack automation | T1110.002 | Host (raw) | ⬚ |
| Hashcat | GPU hash/handshake crack | T1110.002 | CLI wrapper (GPU) | ⬚ |
| Bettercap | MITM / rogue AP / sniff | T1557 | Host (raw) | ⬚ |
| Kismet | Passive wifi discovery | Discovery | CLI wrapper | ⬚ |

## Brute force / cracking
| Tool | Role | ATT&CK | Integration | Status |
|------|------|--------|-------------|--------|
| Hydra | Network service brute force | T1110.001 | CLI wrapper | ⬚ |
| John the Ripper | Hash cracking | T1110.002 | CLI wrapper | ⬚ |

## Defense — detection, hardening, forensics, CTI
| Tool | Role | Integration | Status |
|------|------|-------------|--------|
| **sshd auth logs** | brute-force / anomalous login detection | Pure-python | ✅ `log_analysis` |
| Suricata / Zeek | IDS / network security monitoring | Container | ⬚ |
| Wazuh | SIEM/EDR, log correlation | Container (agent+manager) | ⬚ |
| YARA | Signature malware detection | CLI wrapper | ⬚ |
| Volatility 3 | Memory forensics | CLI wrapper | ⬚ |
| Lynis | Linux hardening audit | CLI wrapper (scoring) | ⬚ |
| MISP | Threat-intel sharing / IOC | Container / external API | ⬚ |
| CyberChef | Data transform/decode | Static web, iframe | ⬚ |

## Cross-cutting feeds (update module)
| Source | Use |
|--------|-----|
| MITRE ATT&CK STIX/TAXII | Technique table + Navigator heatmap (`var/attack.json`) |
| NVD (CVE API) | Flag recent relevant CVEs; enrich scan results |
| Exploit-DB | Correlate scan findings with public PoCs |

## Key takeaway
The missing piece in the ecosystem is not another tool — it is the
**orchestration, scope/audit governance, ATT&CK mapping and unified reporting**
layer that ties these siloed CLIs together. That layer is what this project is.

<div align="center">

# 🛡️ CYBER ORCHESTRATOR ⚔️

**A local-first orchestration, scope-governance and reporting layer for authorized security testing.**

It *wraps* the mature pentest / OSINT / threat-defense toolchain (nmap, nuclei, aircrack-ng, Suricata…) — it does **not** reimplement it. The value is the guided workflow, the blocking legal guardrails, the automatic MITRE ATT&CK mapping and the unified reporting that the ecosystem lacks.

![status](https://img.shields.io/badge/status-MVP-blue) ![python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white) ![api](https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white) ![bind](https://img.shields.io/badge/bind-127.0.0.1%20only-success) ![modules](https://img.shields.io/badge/modules-23-orange) ![tests](https://img.shields.io/badge/tests-passing-brightgreen) ![license](https://img.shields.io/badge/license-see%20repo-lightgrey)

</div>

> ## ⚠️ Authorized use only
> This platform is for a **professional security engineer** performing **explicitly authorized** testing on a **dedicated, isolated lab**. Its legal guardrails (mandatory scope, blocking enforcement, immutable audit) are **controls, not decoration**. Running any offensive module against a system you are not authorized to test is illegal. **You** are responsible for staying inside your written mandate.

---

## 🎨 Design & interactivity

The UI uses the **Liquid Glass** design system (luminous aurora background, translucent glass panes with chromatic-edge refraction, iOS-style spring motion, Inter + IBM Plex Mono). It is **interactive**: a per-engagement **dashboard** (KPIs + recent findings), **toasts**, animated wizard progress, live severity tallies, and a scope panel.

**Manage engagements & scope:** you can now **delete an engagement** (🗑 in the top bar) and **revoke a scope** (Scope panel → *Revoke scope*). Both are confirmed and audited — the immutable, hash-chained **audit log is never erased**, only the live data is removed.

**Reports** are detailed and consulting-grade: cover with overall **risk level**, KPI tiles, severity **donut** + bars, **MITRE ATT&CK tactic coverage**, findings grouped by severity with **evidence + remediation**, per-action technical detail (command, duration, parsed result, raw output), and the verified **audit trail**.

## 📑 Table of contents

1. [What it does](#-what-it-does)
2. [Install (WSL2 / Ubuntu / Kali)](#-install)
3. [A → Z: your first assessment](#-a--z-your-first-assessment)
4. [Understanding the interface](#-understanding-the-interface)
5. [Scope & authorization](#-scope--authorization-the-main-guardrail)
6. [Privilege levels](#-privilege-levels)
7. [📚 Full module reference (how to use each tool)](#-full-module-reference)
8. [Legal guardrails](#-legal-guardrails)
9. [Reports](#-reports)
10. [Deployment & Wi-Fi note](#-deployment--wi-fi)
11. [Project structure](#-project-structure)
12. [Extending with new modules](#-extending)
13. [Tests](#-tests)

---

## ✨ What it does

```
  You (operator)                 Cyber Orchestrator                 Existing tools
 ┌──────────────┐    guided     ┌──────────────────────┐  wraps   ┌────────────────┐
 │  Web UI       │ ───────────► │ scope guard → audit →│ ───────► │ nmap, nuclei,  │
 │ Attack/Defense│              │ run → parse → findings│          │ hydra, yara... │
 │   wizard      │ ◄─────────── │ → MITRE map → report  │ ◄─────── │ (CLI/container)│
 └──────────────┘   findings    └──────────────────────┘  output  └────────────────┘
```

- **One guided workflow** for 23 modules across every offensive & defensive category.
- **Blocking guardrails**: no authorized scope → no active/offensive action. Period.
- **Immutable, hash-chained audit** of every action (tamper-evident).
- **Automatic MITRE ATT&CK** mapping, shown live and in reports.
- **Consulting-grade reports** (themed HTML + PDF).
- **Simulation mode**: a module whose tool isn't installed yet runs with clearly-flagged sample output, so you can learn the whole flow before provisioning.

---

## 🚀 Install

**On WSL2 (Ubuntu), a VM, or bare-metal Debian/Kali:**

```bash
# 1. Get the code
git clone https://github.com/jamesdoe6/cyber-orchestrator.git
cd cyber-orchestrator

# 2. Provision the runtime + tools (see flags below)
sudo ./provisioning/provision.sh            # full toolset
#   sudo ./provisioning/provision.sh --minimal           # core + defense only (fast)
#   sudo ./provisioning/provision.sh --with-containers   # + Docker for MSF/OpenVAS/Wazuh

# 3. Run (loopback only)
cd backend && source .venv/bin/activate && python -m app
```

Then open **http://127.0.0.1:8777/** in your browser (on WSL2, `localhost` is forwarded to Windows automatically).

> 📘 Detailed WSL walkthrough (Docker, localhost, Wi-Fi): [`docs/DEPLOY_WSL.md`](docs/DEPLOY_WSL.md)
> 🧪 No tools installed yet? Everything still runs in **simulation mode** — explore first, provision later.

---

## 🧭 A → Z: your first assessment

This mirrors exactly what you see on screen.

| # | Action | Where | Notes |
|---|--------|-------|-------|
| **1** | Click **`+ Engagement`** | top bar | Give it a name + your operator name, pick **Attack** or **Defense**, *Create*. An *engagement* = one bounded piece of authorized work. |
| **2** | Click **`Scope`**, fill it, *Accept & save* | top bar | Declare the authorized perimeter. Badge flips `no scope` 🔴 → `scope ✓` 🟢. **Required** before any active/offensive module. |
| **3** | Pick a module | left sidebar | Modules are grouped by category. Click one (e.g. *Nmap network scan*). |
| **4** | Follow the step-by-step **assistant** | center | Fill each step, **Next →**. Contextual help + "what to expect" on every step. |
| **5** | Click **▶ Launch** | last step | Scope is re-checked and the action is written to the audit log *before* the tool starts. |
| **6** | Read the **findings** | center + right panel | Severity, asset, and the matching **MITRE ATT&CK** technique appear live. |
| **7** | Click **`Reports`** → *Generate report* | top bar | Themed HTML (+ PDF) with cover, exec summary, scope, findings, ATT&CK, remediation. |

> 💡 **Passive modules** (OSINT, all Defense) don't strictly need a scope — but declaring one keeps your audit trail complete. **Active/offensive** modules are **blocked** without an accepted, in-window scope that covers the target.

---

## 🖥️ Understanding the interface

```
┌───────────────────────────────────────────────────────────────────────────┐
│ CYBERORCH   [engagement ▼]  +Engagement  Scope  [scope✓]  [audit✓(n)]  Reports │  ← top bar
├───────────────┬──────────────────────────────────────┬────────────────────┤
│ CATEGORY      │                                        │ MITRE ATT&CK       │
│  • module     │     GUIDED WIZARD (steps + progress)   │  (of selected      │
│  • module     │     help · fields · Back/Next · Launch │   module, live)    │
│ CATEGORY      │                                        │                    │
│  • module     │     ── results appear here ──          │ FINDINGS THIS      │
│               │     findings table + raw output        │ ENGAGEMENT         │
├───────────────┴──────────────────────────────────────┴────────────────────┤
│                 ⚔ ATTACK (red)          │          🛡 DEFENSE (blue)          │  ← mode tabs
└───────────────────────────────────────────────────────────────────────────┘
```

- **Bottom tabs** switch between **Attack** (red/orange) and **Defense** (blue/green). Each remembers its own state.
- **`scope ✓` / `no scope`** badge = whether the current engagement has an accepted authorization.
- **`audit ✓ (n)`** badge = the hash-chained audit log is intact (`n` events verified). If it ever shows **BROKEN**, the log was tampered with.
- **Right panel** = MITRE ATT&CK techniques for the selected module + a live severity tally for the engagement.

---

## 🎯 Scope & authorization (the main guardrail)

Open **`Scope`** and provide:

| Field | Example | Meaning |
|-------|---------|---------|
| Authorization reference | `MANDATE-2026-014` | The written mandate / engagement letter ID. |
| Authorizing party | `ACME Corp — CISO` | Who signed off. |
| Valid from / until | date-time pickers | The action is blocked outside this window. |
| Targets (one or more) | see below | The **only** systems you may touch. |

**Target types** (choose per row):

| Type | Example value | Matches |
|------|---------------|---------|
| `ip` | `192.0.2.10` | that exact IP |
| `cidr` | `192.0.2.0/24` | any IP in the range |
| `host` / `domain` | `example.com` | that host **and its subdomains** |
| `url` | `https://app.example.com` | that host |
| `ssid` | `MyLab-AP` | that Wi-Fi SSID exactly |

> Anything outside this gets **`status: blocked`** with a reason (`target_out_of_scope`, `outside_window`, `no_authorization`), and the block itself is audited.

---

## 🔐 Privilege levels

Each module declares one. It decides what the scope guard enforces:

| Level | Meaning | Needs accepted scope? |
|-------|---------|-----------------------|
| 🟢 **passive** | No packets to the target (OSINT, local log/forensics) | No (still audited) |
| 🟡 **active** | Touches the target, non-destructive (port/vuln scan) | **Yes** + target in scope |
| 🔴 **offensive** | Exploitation / credential attacks / injection / Wi-Fi | **Yes** + target in scope + global kill-switch ON |

> The **offensive kill-switch** is `CO_OFFENSIVE_ENABLED` (default `true`). Set it `false` in `backend/.env` to disable every 🔴 module globally, regardless of scope.

---

## 📚 Full module reference

> For every module: fill the wizard fields, **Launch**. If the underlying tool isn't installed, you get **simulated** output (clearly flagged). Install the tool to get live results. Install hints assume Debian/Ubuntu/Kali.

### ⚔️ ATTACK

<details>
<summary><b>Reconnaissance / OSINT</b> — theHarvester · Amass · Sherlock · DNS recon · WHOIS (all 🟢 passive)</summary>

| Module | What it does | Key fields (example) | Install | ATT&CK |
|--------|--------------|----------------------|---------|--------|
| **theHarvester** | Emails/subdomains/hosts from public sources | `target` = `example.com`; `sources` = `bing,crtsh,duckduckgo`; `limit` = `200` | `pipx install theHarvester` | T1589/T1590 |
| **Amass** | Passive subdomain enumeration | `target` = `example.com` | `apt install amass` or upstream binary | T1590.002 |
| **Sherlock** | Find a username across social platforms | `target` = `jdoe` | `pipx install sherlock-project` | T1593.001 |
| **DNS recon** | A/AAAA/MX/NS/TXT records (via public resolver) | `target` = `example.com`; `resolver` = `1.1.1.1` | `apt install dnsutils` | T1590.002 |
| **WHOIS** | Domain/IP registration data | `target` = `example.com` | `apt install whois` | T1596 |

*What you get:* lists of emails/subdomains/profiles/records as findings; a weak-SPF note from DNS recon.
</details>

<details>
<summary><b>Network scan</b> — Nmap · Masscan (🟡 active)</summary>

| Module | What it does | Key fields (example) | Install | ATT&CK |
|--------|--------------|----------------------|---------|--------|
| **Nmap network scan** | Ports/services/OS discovery | `target` = `192.0.2.0/24`; `profile` = `top1000` (or `quick`/`full`/`service`); `service_detection` = on; `timing` = `T3` | `apt install nmap` | T1046/T1018 |
| **Masscan** | Very fast port sweep of large ranges | `target` = `192.0.2.0/24`; `ports` = `1-1000`; `rate` = `1000` (keep moderate!) | `apt install masscan` | T1046 |

*What you get:* open ports per host; exposed risky services (SMB, RDP, telnet…) escalated in severity.
</details>

<details>
<summary><b>Vulnerability scan</b> — Nuclei · Nikto (🟡 active)</summary>

| Module | What it does | Key fields (example) | Install | ATT&CK |
|--------|--------------|----------------------|---------|--------|
| **Nuclei** | Template-based scanning (very current) | `target` = `https://app.example.com`; `severity` = `low`+ | upstream binary (provisioning does this) | T1595 |
| **Nikto** | Web server misconfig / dangerous files | `target` = `https://web.example.com` | `apt install nikto` | T1595.002 |

*What you get:* each match becomes a finding with the template/issue severity.
</details>

<details>
<summary><b>Web app pentest</b> — WhatWeb (🟡) · SQLmap (🔴)</summary>

| Module | What it does | Key fields (example) | Install | ATT&CK |
|--------|--------------|----------------------|---------|--------|
| **WhatWeb** | Fingerprint the tech stack/CMS | `target` = `https://app.example.com` | `apt install whatweb` | T1595 |
| **SQLmap** | Detect & characterize SQL injection | `target` = `https://app.example.com/item?id=1`; `level` = `1`; `risk` = `1` | `apt install sqlmap` | T1190 |

*What you get:* detected components (flagged for CVE check); confirmed SQLi marked **critical** with DBMS/type.
</details>

<details>
<summary><b>Brute force / cracking</b> — Hydra · John · Hashcat (🔴 offensive)</summary>

| Module | What it does | Key fields (example) | Install | ATT&CK |
|--------|--------------|----------------------|---------|--------|
| **Hydra** | Test auth strength of a service | `target` = `192.0.2.10`; `service` = `ssh`; `username` = `admin` (or `/path/to/users.txt`); `wordlist` = `/usr/share/wordlists/rockyou.txt`; `tasks` = `4` | `apt install hydra` | T1110.001 |
| **John the Ripper** | Crack captured hashes | `hashfile` = `/home/you/hashes.txt`; `format` = `sha512crypt` (blank=auto); `wordlist` = `/usr/share/wordlists/rockyou.txt` | `apt install john` | T1110.002 |
| **Hashcat** | GPU cracking (hashes / WPA) | `hashfile` = `/home/you/hash.hc22000`; `mode` = `22000` (WPA) or `0` (MD5)…; `wordlist` = `/usr/share/wordlists/rockyou.txt` | `apt install hashcat` | T1110.002 |

> John/Hashcat have **no network target** (they work on files you captured legitimately) — they still require an accepted scope + the kill-switch, but skip the perimeter match.
*What you get:* recovered credentials/passphrases as high/critical findings + remediation.
</details>

<details>
<summary><b>Wi-Fi</b> — Wifite (🔴 offensive, host-only)</summary>

| Module | What it does | Key fields (example) | Install | ATT&CK |
|--------|--------------|----------------------|---------|--------|
| **Wifite** | Capture handshake + WPA/WPA2 dictionary audit | `target` = `MyLab-AP` (must be a scope target of type `ssid`); `interface` = `wlan0mon`; `wordlist` = `/usr/share/wordlists/rockyou.txt` | `apt install wifite aircrack-ng` | T1110.002 |

> ⛔ **Does NOT work in WSL2** (no monitor mode). Needs bare-metal/VM + a monitor-capable USB Wi-Fi adapter. First put the card in monitor mode: `sudo airmon-ng start wlan0`.
*What you get:* handshake status / recovered passphrase (critical) + remediation.
</details>

<details>
<summary><b>Exploitation</b> — Searchsploit (🟢) · Metasploit (🔴)</summary>

| Module | What it does | Key fields (example) | Install | ATT&CK |
|--------|--------------|----------------------|---------|--------|
| **Searchsploit** | Look up public exploits (Exploit-DB) for a product/version | `target` = `OpenSSH 7.2` | `apt install exploitdb` | T1595 |
| **Metasploit** | Run one MSF module against a target | `module` = `auxiliary/scanner/smb/smb_version`; `target` (RHOSTS) = `192.0.2.10`; `options` = `set RPORT 445` (one per line) | Kali, installer, or Docker image | T1190/T1210 |

*What you get:* referenced PoCs (medium); MSF module output; an opened session is marked **critical**.
</details>

### 🛡️ DEFENSE *(all 🟢 passive / local)*

<details>
<summary><b>Intrusion detection</b> — Suricata alerts</summary>

| Module | What it does | Key fields (example) | Install | ATT&CK |
|--------|--------------|----------------------|---------|--------|
| **Suricata alerts** | Ingest & prioritize IDS alerts from `eve.json` | `eve_path` = `/var/log/suricata/eve.json` (empty = sample); `min_severity` = `3` (1=high only) | `apt install suricata` (to produce eve.json) | T1071 |

*What you get:* alerts aggregated by signature/source with severity + triage advice.
</details>

<details>
<summary><b>Hardening</b> — Lynis</summary>

| Module | What it does | Key fields | Install |
|--------|--------------|------------|---------|
| **Lynis** | Audit local host hardening; hardening index + suggestions | `profile` = `system` | `apt install lynis` |

*What you get:* a hardening index (0–100) finding + each warning/suggestion with remediation.
</details>

<details>
<summary><b>Log analysis</b> — Auth log analysis</summary>

| Module | What it does | Key fields (example) | Install |
|--------|--------------|----------------------|---------|
| **Auth log analysis** | sshd brute-force & suspicious-success detection | `log_text` = paste lines, **or** `log_path` = `/var/log/auth.log`; `bruteforce_threshold` = `5` | built-in (pure Python) |

*What you get:* per-IP brute-force findings; a successful login after failures → **critical** + remediation.
</details>

<details>
<summary><b>Malware / forensics</b> — YARA · Volatility 3</summary>

| Module | What it does | Key fields (example) | Install |
|--------|--------------|----------------------|---------|
| **YARA** | Scan files/dirs against YARA rules | `rules` = `/home/you/rules.yar`; `target` = `/suspect/path`; `recursive` = on | `apt install yara` |
| **Volatility 3** | RAM-dump forensics | `dump` = `/home/you/mem.raw`; `plugin` = `windows.pslist` (or `netscan`/`malfind`/`linux.pslist`) | `apt install volatility3` (binary `vol`) |

*What you get:* rule matches (high) with IR advice; suspicious processes/artifacts from memory.
</details>

<details>
<summary><b>Threat intel (CTI)</b> — Recent CVEs (NVD)</summary>

| Module | What it does | Key fields (example) | Needs |
|--------|--------------|----------------------|-------|
| **CTI: recent CVEs** | Pull recently published CVEs from NVD | `days` = `7`; `min_cvss` = `7` | outbound HTTPS (optional `CO_NVD_API_KEY` raises rate limits) |

*What you get:* recent high/critical CVEs to map against your inventory. Offline → a flagged sample.
</details>

---

## ⚖️ Legal guardrails

1. **Mandatory scope** — active/offensive modules require an accepted, time-boxed authorization covering the target.
2. **Blocking, not warnings** — a single chokepoint (`orchestrator.launch` → `security/scope.py`) refuses out-of-scope / expired / unauthorized / kill-switched runs with `status=blocked`.
3. **Immutable audit** — every action is appended to a **hash-chained** log (`security/audit.py`) with a second on-disk copy; `GET /api/audit/verify` detects any tampering (the `audit ✓` badge).
4. **Authorization in every report** — cover page + a dedicated legal section carry perimeter, mandate, party, dates, author.

---

## 📄 Reports

**`Reports` → Generate report for current engagement.** You get a themed document (red for Attack, blue for Defense) with: cover page, executive summary, authorization/legal scope, findings-by-severity chart, findings table, per-action technical detail (command + raw output annex), MITRE ATT&CK mapping, and — Defense only — a prioritized remediation plan. HTML always; **PDF** when WeasyPrint's native libs are present (the provisioning script installs them). Downloadable from the in-app report library.

---

## 🧰 Deployment & Wi-Fi

- **WSL2 / Ubuntu**: full guide in [`docs/DEPLOY_WSL.md`](docs/DEPLOY_WSL.md). Everything works **except Wi-Fi monitor mode** (WSL2 can't access the radio).
- **Dedicated VM / bare-metal (for Wi-Fi)**: use **Kali** + a monitor-capable USB Wi-Fi adapter (e.g. AR9271). `provision.sh --minimal` sets up the runtime.
- **Containers**: `provision.sh --with-containers` installs Docker for OpenVAS / Metasploit / Wazuh images.

---

## 🗂️ Project structure

```
cyber-orchestrator/
├── README.md                    ← you are here
├── docs/  ARCHITECTURE.md · TOOLS_CATALOG.md · DEPLOY_WSL.md
├── provisioning/provision.sh    ← Debian/Kali/Ubuntu(+WSL) setup
├── frontend/index.html          ← local SPA (tabs, wizard, MITRE, reports)
└── backend/
    ├── requirements.txt · .env.example
    ├── app/
    │   ├── main.py config.py database.py models.py schemas.py
    │   ├── orchestrator.py       ← the single execution chokepoint
    │   ├── mitre.py updater.py
    │   ├── security/ scope.py · audit.py        ← the guardrails
    │   ├── plugins/ base.py registry.py
    │   │   ├── attack/   (16 modules)
    │   │   └── defense/  ( 6 modules)
    │   ├── routers/ engagements · plugins · runs · audit · reports · updates
    │   └── reporting/ generator.py + templates/ (_base, attack, defense)
    └── tests/test_core.py
```

---

## 🧩 Extending

Add a module by dropping a `BasePlugin` subclass in `backend/app/plugins/attack/` or `defense/`:

```python
from ...models import Mode, Severity
from ..base import BasePlugin, FindingDraft, Param, PluginMeta, Step

class MyTool(BasePlugin):
    meta = PluginMeta(slug="mytool", name="My Tool", mode=Mode.attack,
        category="Network scan", privilege="active", binary="mytool",
        attack_techniques=["T1046"], description="…",
        params=[Param("target", "Target", "string")],
        steps=[Step("t","1. Target","help", ["target"], "what to expect")])
    def build_argv(self, p):  return ["mytool", p["target"]]
    def simulate(self, p):    return "sample output"
    def parse(self, raw, p):  return {"data": raw}
    def findings(self, parsed, p): return [FindingDraft(title="…", severity=Severity.info)]
```

The registry auto-discovers it; the UI, scope guard, audit and reporting pick it up with **zero** core changes. Container/API tools (OpenVAS, Wazuh, MISP, BloodHound, C2) are documented as extension points in [`docs/TOOLS_CATALOG.md`](docs/TOOLS_CATALOG.md).

---

## 🧪 Tests

```bash
cd backend && python -m pytest -q
```
Covers scope blocking (no auth / out-of-perimeter), defense detection, mode-mismatch, audit-chain integrity, and report generation.

---

<div align="center">
<sub>Built for authorized security work. Stay inside your mandate. 🛡️</sub>
</div>

# Deploying on WSL2 (Ubuntu)

WSL2 *is* a real Linux kernel, so the platform and almost every tool run
natively. The one hard limitation is **Wi-Fi monitor mode / packet injection**,
which WSL2 cannot do (no direct radio access). Everything else works.

## 1. Get the code (inside your WSL Ubuntu shell)

```bash
cd ~
git clone https://github.com/jamesdoe6/cyber-orchestrator.git
cd cyber-orchestrator
```

## 2. Provision (installs runtime + tools)

```bash
# First run — core + defensive tooling only (fast, safe):
sudo ./provisioning/provision.sh --minimal

# Full toolset (adds masscan, nuclei, nikto, hydra, john, hashcat, yara,
# lynis, suricata, amass, theHarvester, sherlock, exploitdb, aircrack...):
sudo ./provisioning/provision.sh

# Also install Docker for containerised tools (Metasploit, OpenVAS, Wazuh):
sudo ./provisioning/provision.sh --with-containers
```

If a specific tool isn't in Ubuntu's repos, the script fetches upstream
binaries (nuclei, amass) or uses pipx (theHarvester, sherlock). Any tool that
still isn't present simply runs in **simulation mode** — the UI/workflow is
unaffected; you just don't get live output until it's installed.

## 3. Run

```bash
cd ~/cyber-orchestrator/backend
source .venv/bin/activate
python -m app
```

Then open **http://127.0.0.1:8777/** in your Windows browser — WSL2 forwards
`localhost` automatically. The server binds to loopback only.

## 4. Docker on WSL2

Two options:
- **Docker Desktop (Windows)** with "WSL integration" enabled for your distro
  (Settings → Resources → WSL integration). Recommended.
- **Docker engine inside WSL**: `sudo ./provisioning/provision.sh --with-containers`,
  then `sudo service docker start` (WSL2 often has no systemd, so use `service`,
  or enable systemd in `/etc/wsl.conf` with `[boot] systemd=true` and `wsl --shutdown`).

## 5. Wi-Fi (the exception)

The `wifite` module needs a wireless interface in monitor mode. **This is not
possible in WSL2.** For real Wi-Fi assessments:
- Run the platform on **bare-metal Linux** or a **dedicated VM** (VirtualBox/
  VMware/Proxmox) with a **USB Wi-Fi adapter** supporting monitor mode
  (e.g. Atheros AR9271, Realtek RTL8812AU), passed through to that VM.
- `usbipd-win` can forward a USB NIC into WSL2, but monitor-mode drivers are
  usually missing — treat WSL as "everything but Wi-Fi".

## 6. Where the data lives

Runtime data (SQLite DB, audit log, generated reports) is written under
`backend/var/` and is git-ignored. Reports are also downloadable from the UI's
report library.

## 7. Dedicated-VM alternative (for Wi-Fi + full isolation)

Use **Kali Linux** in a VM: most tools are preinstalled, so
`sudo ./provisioning/provision.sh --minimal` is enough to set up the runtime,
and you get real Wi-Fi via a passed-through USB adapter.

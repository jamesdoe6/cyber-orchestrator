#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Cyber Orchestrator — provisioning for Debian 12 / Kali / Ubuntu (incl. WSL2).
#
# Installs the orchestration core's runtime plus the CLI tools the shipped
# plugins wrap. For a DEDICATED lab environment used for AUTHORIZED testing.
#
# Usage:  sudo ./provision.sh [--with-containers] [--minimal]
#   --minimal          core + nmap + defensive tooling only (safe first run)
#   --with-containers  also install Docker (for Metasploit/OpenVAS/Wazuh/...)
# ---------------------------------------------------------------------------
set -euo pipefail

MINIMAL=0; WITH_CONTAINERS=0
for arg in "$@"; do case "$arg" in
  --minimal) MINIMAL=1 ;;
  --with-containers) WITH_CONTAINERS=1 ;;
  *) echo "unknown arg: $arg"; exit 2 ;;
esac; done
[[ $EUID -ne 0 ]] && { echo "Run as root (sudo)."; exit 1; }

. /etc/os-release 2>/dev/null || true
IS_WSL=0; grep -qiE "microsoft|wsl" /proc/version 2>/dev/null && IS_WSL=1
echo "[*] Base: ${PRETTY_NAME:-unknown}  (WSL=$IS_WSL)"

if [[ $IS_WSL -eq 1 ]]; then
  cat <<'WSL'
[!] WSL2 detected.
    - Everything EXCEPT Wi-Fi works fine here (nmap, nuclei, hydra, defense...).
    - Wi-Fi monitor mode / packet injection does NOT work in WSL2: it has no
      direct access to the radio. The `wifite` module will only ever simulate.
      For real Wi-Fi work use bare-metal Linux or a VM with a USB Wi-Fi adapter
      (usbipd-win can forward a USB NIC into WSL2, but monitor-mode support is
      hardware/driver dependent and often unavailable).
WSL
fi

export DEBIAN_FRONTEND=noninteractive
echo "[*] System base + core deps…"
apt-get update -y
apt-get install -y --no-install-recommends \
  python3 python3-venv python3-pip pipx git curl wget ca-certificates \
  libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev \
  nmap dnsutils whois

if [[ $MINIMAL -eq 0 ]]; then
  echo "[*] Attack CLI tools (apt; names vary by distro/repo)…"
  apt-get install -y --no-install-recommends \
    masscan nikto hydra john hashcat whatweb exploitdb \
    aircrack-ng wifite kismet \
    || echo "[!] Some apt tools unavailable here; see notes below."

  echo "[*] Defense CLI tools…"
  apt-get install -y --no-install-recommends yara lynis suricata volatility3 \
    || echo "[!] Some defense tools unavailable via apt; install from upstream."

  echo "[*] Python-packaged OSINT tools via pipx (isolated)…"
  for t in theHarvester sherlock-project; do
    pipx install "$t" 2>/dev/null || echo "[!] pipx install $t failed."
  done
  # amass + nuclei: Go binaries, not reliably in apt — fetch upstream releases.
  echo "[*] nuclei / amass (upstream binaries)…"
  ARCH=$(dpkg --print-architecture); [[ "$ARCH" == "amd64" ]] && GOARCH=amd64 || GOARCH=arm64
  for pd in "nuclei|projectdiscovery/nuclei" "amass|owasp-amass/amass"; do
    name=${pd%%|*}; repo=${pd##*|}
    command -v "$name" >/dev/null 2>&1 && continue
    url=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" \
          | grep -oE "https://[^\" ]*linux_${GOARCH}\.zip" | head -1) || true
    if [[ -n "${url:-}" ]]; then
      tmp=$(mktemp -d); (cd "$tmp" && curl -fsSL "$url" -o t.zip && unzip -oq t.zip \
        && install -m755 "$name" /usr/local/bin/ 2>/dev/null) && echo "   installed $name" \
        || echo "[!] $name install failed"; rm -rf "$tmp"
    else echo "[!] could not resolve $name release URL; install manually."; fi
  done

  echo "[*] Metasploit (official installer; large)…"
  if ! command -v msfconsole >/dev/null 2>&1; then
    if [[ $WITH_CONTAINERS -eq 1 ]]; then
      echo "   will use the Docker image instead (see below)."
    else
      curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
        -o /tmp/msfinstall && chmod +x /tmp/msfinstall && /tmp/msfinstall \
        || echo "[!] Metasploit install skipped; use --with-containers for the Docker image."
    fi
  fi

  echo "[*] Wordlists…"
  apt-get install -y wordlists seclists 2>/dev/null || true
  [[ -f /usr/share/wordlists/rockyou.txt.gz ]] && gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
fi

if [[ $WITH_CONTAINERS -eq 1 ]]; then
  echo "[*] Docker…"
  if ! command -v docker >/dev/null 2>&1; then curl -fsSL https://get.docker.com | sh; fi
  systemctl enable --now docker 2>/dev/null || service docker start 2>/dev/null || \
    echo "[i] On WSL2 without systemd, start Docker Desktop with WSL integration, or 'sudo service docker start'."
  cat <<'DOCK'
[i] Containerised tools — pull on demand:
    docker pull metasploitframework/metasploit-framework
    docker pull mikesplain/openvas            # OpenVAS/Greenbone
    docker pull wazuh/wazuh-manager           # Wazuh SIEM
    docker pull owasp/dependency-check        # (example)
DOCK
fi

# --- Application runtime ---
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "[*] App dir: $APP_DIR"
cd "$APP_DIR/backend"
echo "[*] Python venv + dependencies…"
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Capability for non-root raw scanning (nmap)…"
setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)" 2>/dev/null || true
cat > /etc/sudoers.d/cyberorch <<'SUDO'
# Wi-Fi monitor mode & injection need root. Grant the operator SPECIFIC commands
# (edit the username). Not applicable under WSL2 (no monitor mode).
# cyberop ALL=(root) NOPASSWD: /usr/sbin/airmon-ng, /usr/bin/aircrack-ng, /usr/sbin/iw, /usr/bin/wifite
SUDO

cat <<DONE

[✓] Provisioning complete.
    Start (loopback only):
      cd $APP_DIR/backend && . .venv/bin/activate && python -m app
    Open http://127.0.0.1:8777/

[i] Tools not installed will run in clearly-flagged SIMULATION mode — the
    whole workflow still works; install a tool to get live results.
[!] Authorized testing only, inside your declared scope.
DONE

#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Cyber Orchestrator — VM provisioning (Debian 12 / Kali).
#
# Installs the orchestration core's runtime plus the CLI tools the bundled and
# planned plugins wrap. Intended for a DEDICATED, ISOLATED lab VM used only for
# AUTHORIZED testing. Review before running; it installs offensive tooling.
#
# Usage:  sudo ./provision.sh [--with-containers] [--minimal]
#   --minimal         core + nmap + log tooling only (good for a first run)
#   --with-containers install Docker for the containerised tools (OpenVAS, MSF…)
# ---------------------------------------------------------------------------
set -euo pipefail

MINIMAL=0
WITH_CONTAINERS=0
for arg in "$@"; do
  case "$arg" in
    --minimal) MINIMAL=1 ;;
    --with-containers) WITH_CONTAINERS=1 ;;
    *) echo "unknown arg: $arg"; exit 2 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then echo "Run as root (sudo)."; exit 1; fi

. /etc/os-release || true
echo "[*] Base distro: ${PRETTY_NAME:-unknown}"

echo "[*] System packages…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  python3 python3-venv python3-pip git curl ca-certificates \
  libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev \
  nmap

if [[ $MINIMAL -eq 0 ]]; then
  echo "[*] Core wrapped CLI tools (CLI-wrapper plugins)…"
  # Available in Debian/Kali repos. On Debian some live in contrib/non-free or
  # are best installed from upstream; adjust per your baseline.
  apt-get install -y --no-install-recommends \
    masscan nikto hydra john hashcat whatweb dnsutils \
    aircrack-ng kismet theharvester yara lynis || \
    echo "[!] Some tools unavailable in this repo; install from upstream as needed."

  echo "[*] Python-packaged tools (isolated with pipx)…"
  apt-get install -y pipx || python3 -m pip install --user pipx
  for t in sqlmap recon-ng spiderfoot; do
    pipx install "$t" 2>/dev/null || echo "[!] pipx install $t failed; install manually."
  done
fi

if [[ $WITH_CONTAINERS -eq 1 ]]; then
  echo "[*] Docker (for containerised tools: OpenVAS, Metasploit, BloodHound, Wazuh, Suricata, MISP)…"
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
  echo "[i] Pull tool images on demand, e.g.:"
  echo "    docker pull metasploitframework/metasploit-framework"
  echo "    docker pull mikesplain/openvas"
fi

# ---------------------------------------------------------------------------
# Application runtime
# ---------------------------------------------------------------------------
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "[*] App dir: $APP_DIR"
cd "$APP_DIR/backend"

echo "[*] Python virtualenv + dependencies…"
python3 -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# ---------------------------------------------------------------------------
# Privileges for low-level network operations (wifi monitor mode, raw scans)
# ---------------------------------------------------------------------------
echo "[*] Capabilities for non-root raw scanning (nmap)…"
setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)" || true
cat > /etc/sudoers.d/cyberorch <<'SUDO'
# Wifi monitor mode & packet injection need root. Grant the operator the
# SPECIFIC commands rather than blanket root. Edit the username below.
# cyberop ALL=(root) NOPASSWD: /usr/sbin/airmon-ng, /usr/bin/aircrack-ng, /usr/sbin/iw
SUDO
echo "[i] Edit /etc/sudoers.d/cyberorch to grant your operator the wifi commands."

echo
echo "[✓] Provisioning complete."
echo "    Start the platform (loopback only):"
echo "      cd $APP_DIR/backend && . .venv/bin/activate && python -m app"
echo "    Then open http://127.0.0.1:8777/"
echo
echo "[!] Reminder: use only on networks/targets you are explicitly authorized to test."

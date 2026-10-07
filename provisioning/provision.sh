#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Cyber Orchestrator — provisioning for Debian 12 / Kali / Ubuntu (incl. WSL2).
# Installs the runtime + EVERY wrapped tool into /usr/local/bin (so the app
# always finds them). Packages are installed ONE BY ONE so a single missing
# package never aborts the rest. Prints a real/missing inventory at the end.
#
# Usage:  sudo ./provision.sh [--core-only] [--with-metasploit] [--verify-only]
# ---------------------------------------------------------------------------
set -uo pipefail
CORE_ONLY=0; WITH_MSF=0; VERIFY_ONLY=0
for a in "$@"; do case "$a" in
  --core-only) CORE_ONLY=1;; --with-metasploit) WITH_MSF=1;;
  --verify-only) VERIFY_ONLY=1;; *) echo "unknown arg: $a"; exit 2;; esac; done

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUSER="${SUDO_USER:-$(whoami)}"
export GOBIN=/usr/local/bin GOPROXY=https://proxy.golang.org,direct
export PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
export DEBIAN_FRONTEND=noninteractive
ALL_BINS="nmap masscan enum4linux-ng dig whois theHarvester amass subfinder sherlock maigret holehe phoneinfoga waybackurls exiftool nuclei nikto httpx wafw00f whatweb ffuf wpscan sslscan dalfox sqlmap hydra john hashcat kerbrute nxc searchsploit msfconsole wifite lynis ssh-audit yara vol binwalk olevba tshark clamscan chkrootkit trivy gitleaks osqueryi bash"

inventory(){
  echo; echo "================ TOOL INVENTORY ================"
  local ok=0 miss=0
  for b in $ALL_BINS; do
    if command -v "$b" >/dev/null 2>&1; then printf "  [OK ] %-16s %s\n" "$b" "$(command -v "$b")"; ok=$((ok+1))
    else printf "  [ -- ] %-16s MISSING\n" "$b"; miss=$((miss+1)); fi
  done
  echo "------------------------------------------------"; echo "  installed: $ok   missing: $miss"
  echo "================================================"
}
[[ $VERIFY_ONLY -eq 1 ]] && { inventory; exit 0; }
[[ $EUID -ne 0 ]] && { echo "Run as root (sudo)."; exit 1; }

apt_each(){ for p in "$@"; do
  dpkg -s "$p" >/dev/null 2>&1 && continue
  apt-get install -y --no-install-recommends "$p" >/dev/null 2>&1 && echo "   + $p" || echo "   [!] apt: $p unavailable on this distro"
done; }
pipx_one(){ command -v "$2" >/dev/null 2>&1 && return; pipx install "$1" >/dev/null 2>&1 && echo "   + $2" || echo "   [!] pipx $1 failed (needs build deps/newer python)"; }
go_one(){ command -v "$2" >/dev/null 2>&1 && return; echo "   go: $2"; go install "$1" >/dev/null 2>&1 && echo "   + $2" || echo "   [!] go install $2 failed (needs recent Go)"; }

. /etc/os-release 2>/dev/null || true
IS_WSL=0; grep -qiE "microsoft|wsl" /proc/version 2>/dev/null && IS_WSL=1
echo "[*] Base: ${PRETTY_NAME:-unknown}  WSL=$IS_WSL  user=$RUSER"
[[ $IS_WSL -eq 1 ]] && echo "[!] WSL2: everything works EXCEPT Wi-Fi monitor mode (wifite)."

echo "[*] apt update + base/build deps…"
apt-get update -y >/dev/null 2>&1 || echo "[!] apt update had warnings"
apt_each python3 python3-venv python3-pip python3-dev pipx git curl wget unzip jq ca-certificates \
         build-essential libssl-dev libffi-dev libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
         golang-go ruby ruby-dev snapd

echo "[*] apt security tools (one-by-one)…"
apt_each nmap masscan nikto whatweb sqlmap hydra john hashcat dnsutils whois \
         yara lynis binwalk chkrootkit clamav aircrack-ng tshark \
         libimage-exiftool-perl sslscan ffuf wifite

if [[ $CORE_ONLY -eq 0 ]]; then
  echo "[*] Python tools via pipx -> /usr/local/bin…"
  pipx_one theHarvester theHarvester
  pipx_one "git+https://github.com/laramies/theHarvester" theHarvester
  pipx_one sherlock-project sherlock
  pipx_one maigret maigret
  pipx_one holehe holehe
  pipx_one wafw00f wafw00f
  pipx_one netexec nxc
  pipx_one "git+https://github.com/Pennyw0rth/NetExec" nxc
  pipx_one volatility3 vol
  pipx_one oletools olevba
  pipx_one ssh-audit ssh-audit
  pipx_one enum4linux-ng enum4linux-ng
  pipx_one "git+https://github.com/cddmp/enum4linux-ng" enum4linux-ng

  if ! command -v theHarvester >/dev/null 2>&1; then
    echo "[*] theHarvester (dedicated venv fallback)…"
    rm -rf /opt/theHarvester
    git clone --depth 1 --branch 4.6.0 https://github.com/laramies/theHarvester.git /opt/theHarvester >/dev/null 2>&1 \
      && python3 -m venv /opt/theHarvester/venv \
      && /opt/theHarvester/venv/bin/pip install -q --upgrade pip >/dev/null 2>&1 \
      && /opt/theHarvester/venv/bin/pip install -q /opt/theHarvester >/dev/null 2>&1 \
      && ln -sf /opt/theHarvester/venv/bin/theHarvester /usr/local/bin/theHarvester \
      && echo "   + theHarvester (venv)" || echo "   [!] theHarvester venv install failed"
  fi

  echo "[*] Go tools -> /usr/local/bin…"
  go_one github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest subfinder
  go_one github.com/projectdiscovery/httpx/cmd/httpx@latest httpx
  go_one github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest nuclei
  go_one github.com/tomnomnom/waybackurls@latest waybackurls
  go_one github.com/hahwul/dalfox/v2@latest dalfox
  go_one github.com/gitleaks/gitleaks/v8@latest gitleaks
  command -v amass >/dev/null 2>&1 || go_one github.com/owasp-amass/amass/v4/...@master amass
  command -v ffuf  >/dev/null 2>&1 || go_one github.com/ffuf/ffuf/v2@latest ffuf
  command -v nuclei >/dev/null 2>&1 && su - "$RUSER" -c "nuclei -update-templates" >/dev/null 2>&1 || true

  echo "[*] searchsploit (Exploit-DB via git)…"
  if ! command -v searchsploit >/dev/null 2>&1; then
    rm -rf /opt/exploitdb 2>/dev/null
    git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb >/dev/null 2>&1 \
      && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit && echo "   + searchsploit" \
      || echo "   [!] searchsploit (exploitdb) clone failed"
  fi

  echo "[*] wpscan (ruby gem)…"
  command -v wpscan >/dev/null 2>&1 || { gem install wpscan >/dev/null 2>&1 && echo "   + wpscan" || echo "   [!] wpscan gem failed"; }

  echo "[*] Upstream release binaries…"
  ARCH=$(dpkg --print-architecture); [[ "$ARCH" == "amd64" ]] && A=amd64 || A=arm64
  if ! command -v kerbrute >/dev/null 2>&1; then
    curl -fsSL "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_${A}" -o /usr/local/bin/kerbrute \
      && chmod +x /usr/local/bin/kerbrute && echo "   + kerbrute" || echo "   [!] kerbrute failed"; fi
  if ! command -v phoneinfoga >/dev/null 2>&1; then
    bash <(curl -fsSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install) >/dev/null 2>&1 \
      && install -m755 ./phoneinfoga /usr/local/bin/ 2>/dev/null && rm -f ./phoneinfoga && echo "   + phoneinfoga" || echo "   [!] phoneinfoga failed"; fi
  if ! command -v trivy >/dev/null 2>&1; then
    curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin >/dev/null 2>&1 \
      && echo "   + trivy" || echo "   [!] trivy failed"; fi
  if ! command -v osqueryi >/dev/null 2>&1; then
    curl -fsSL "https://pkg.osquery.io/deb/osquery_5.12.1-1.linux_${A}.deb" -o /tmp/osquery.deb 2>/dev/null \
      && apt-get install -y /tmp/osquery.deb >/dev/null 2>&1 && echo "   + osquery" || echo "   [!] osquery failed"; rm -f /tmp/osquery.deb; fi
fi

if [[ $WITH_MSF -eq 1 ]] && ! command -v msfconsole >/dev/null 2>&1; then
  echo "[*] Metasploit (large ~1.5GB)…"
  curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -o /tmp/msfinstall \
    && chmod +x /tmp/msfinstall && /tmp/msfinstall >/dev/null 2>&1 && echo "   + metasploit" || echo "   [!] metasploit failed"
fi

echo "[*] Persist tool PATH…"
cat > /etc/profile.d/cyberorch-path.sh <<'PTH'
export PATH="/usr/local/bin:$HOME/.local/bin:$HOME/go/bin:/snap/bin:/opt/metasploit-framework/bin:$PATH"
PTH

echo "[*] Python venv + app deps…"
cd "$APP_DIR/backend"; [[ -d .venv ]] || python3 -m venv .venv
. .venv/bin/activate && pip install --upgrade pip >/dev/null && pip install -r requirements.txt >/dev/null
setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)" 2>/dev/null || true
chown -R "$RUSER":"$RUSER" "$APP_DIR" 2>/dev/null || true

inventory
echo; echo "[✓] Done. Start: cd $APP_DIR/backend && . .venv/bin/activate && python -m app"
echo "    Re-check anytime: sudo ./provisioning/provision.sh --verify-only"

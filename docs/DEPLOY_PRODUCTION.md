# Production deployment — A → Z

This turns the dev setup (`python -m app` + SQLite) into a hardened, always-on
service on your **dedicated lab VM**: PostgreSQL, Gunicorn+Uvicorn under systemd,
optional token auth, PDF reports, backups, and secure remote access.

> Cyber Orchestrator is a **single-operator, loopback-bound** tool. "Production"
> here means *reliable and hardened on your VM*, not a public multi-tenant service.
> **Never expose port 8777 to a network.** Reach it over an SSH tunnel.

---

## 0. Target host

A dedicated, isolated **Debian 12 / Kali** VM (or bare-metal). Keep it patched.
Do **not** run this on a shared or production business server.

## 1. Create a service user & install location

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin cyberorch
sudo mkdir -p /opt/cyber-orchestrator
sudo chown cyberorch:cyberorch /opt/cyber-orchestrator

# Clone as the service user
sudo -u cyberorch git clone https://github.com/jamesdoe6/cyber-orchestrator.git /opt/cyber-orchestrator
```

## 2. System dependencies + tools

```bash
cd /opt/cyber-orchestrator
sudo ./provisioning/provision.sh            # runtime + security tools + WeasyPrint libs
# (the script also creates backend/.venv and installs requirements.txt)
```

> PDF reports need WeasyPrint's native libs (`libpango…`, installed by the script).
> Verify later with: a generated report should produce both HTML **and** PDF.

## 3. PostgreSQL

```bash
sudo apt-get install -y postgresql
sudo -u postgres psql -c "CREATE USER cyberorch WITH PASSWORD 'CHANGE_ME_STRONG';"
sudo -u postgres psql -c "CREATE DATABASE cyberorch OWNER cyberorch;"
```

Tables are created automatically on first start (no migration step needed).

## 4. Configuration (`backend/.env`)

```bash
sudo -u cyberorch cp /opt/cyber-orchestrator/backend/.env.example /opt/cyber-orchestrator/backend/.env
# Generate an API token:
python3 -c "import secrets;print('CO_API_TOKEN='+secrets.token_urlsafe(32))"
sudo -u cyberorch nano /opt/cyber-orchestrator/backend/.env
```

Set at minimum:
```ini
CO_DATABASE_URL=postgresql+psycopg://cyberorch:CHANGE_ME_STRONG@127.0.0.1/cyberorch
CO_API_TOKEN=<the token you generated>
CO_ENFORCE_SCOPE=true
CO_OFFENSIVE_ENABLED=true          # set false to hard-disable offensive modules
CO_REPORT_AUTHOR=Your Name
CO_REPORT_ORG=Your Lab
```
`chmod 600 backend/.env` — it holds secrets.

## 5. Run as a systemd service

```bash
sudo cp /opt/cyber-orchestrator/provisioning/cyberorch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cyberorch
sudo systemctl status cyberorch        # should be active (running)
journalctl -u cyberorch -f             # live logs
```

The unit runs **Gunicorn with Uvicorn workers**, bound to `127.0.0.1:8777`,
restarts on failure, and grants `CAP_NET_RAW`/`CAP_NET_ADMIN` so nmap/masscan
can raw-scan **without root**.

## 6. Verify

```bash
curl -s http://127.0.0.1:8777/api/health
# -> {"status":"ok", ..., "auth_required":true}
curl -s -H "X-API-Token: <token>" http://127.0.0.1:8777/api/plugins | head -c 200
```

## 7. Secure remote access (recommended: SSH tunnel)

From your workstation:
```bash
ssh -L 8777:127.0.0.1:8777 youruser@your-vm
```
Then browse **http://127.0.0.1:8777/** locally. The UI will prompt once for the
API token and remember it. No port is ever exposed on the network.

<details>
<summary>Alternative: nginx + TLS + Basic Auth (if you can't use SSH)</summary>

```nginx
server {
  listen 443 ssl;
  server_name cyberorch.lab.local;
  ssl_certificate     /etc/ssl/certs/cyberorch.crt;
  ssl_certificate_key /etc/ssl/private/cyberorch.key;
  auth_basic "Cyber Orchestrator";
  auth_basic_user_file /etc/nginx/.htpasswd;   # htpasswd -c ... cyberorch
  location / { proxy_pass http://127.0.0.1:8777; proxy_set_header Host $host; }
}
```
Keep `CO_API_TOKEN` set as a second factor, and firewall 443 to your admin IPs.
</details>

## 8. Firewall

```bash
sudo apt-get install -y ufw
sudo ufw default deny incoming
sudo ufw allow OpenSSH
sudo ufw enable           # 8777 is NOT opened — reached via SSH tunnel only
```

## 9. Backups

The audit log and findings are evidentiary — back them up.
```bash
# /etc/cron.daily/cyberorch-backup  (chmod +x)
#!/bin/sh
d=/var/backups/cyberorch; mkdir -p "$d"
sudo -u postgres pg_dump cyberorch | gzip > "$d/db-$(date +%F).sql.gz"
cp /opt/cyber-orchestrator/backend/var/audit/audit.log "$d/audit-$(date +%F).log" 2>/dev/null || true
find "$d" -mtime +30 -delete
```

## 10. Updates

```bash
cd /opt/cyber-orchestrator
sudo -u cyberorch git pull
sudo -u cyberorch backend/.venv/bin/pip install -r backend/requirements.txt
sudo systemctl restart cyberorch
```

## 11. Wi-Fi note

Wi-Fi modules need monitor mode, which a plain VM/WSL can't provide. For real
Wi-Fi work, run on hardware (or a VM with a passed-through monitor-capable USB
adapter) — see `docs/DEPLOY_WSL.md`.

---

### Production checklist
- [ ] Dedicated, patched, isolated VM
- [ ] Non-root `cyberorch` service user
- [ ] PostgreSQL configured, `CO_DATABASE_URL` set
- [ ] `CO_API_TOKEN` set, `.env` is `chmod 600`
- [ ] systemd service enabled + running
- [ ] Bound to 127.0.0.1; reached via SSH tunnel (or nginx+TLS+auth)
- [ ] Firewall denies inbound except SSH
- [ ] PDF reports generate (WeasyPrint libs present)
- [ ] Daily DB + audit-log backups
- [ ] `CO_ENFORCE_SCOPE=true`

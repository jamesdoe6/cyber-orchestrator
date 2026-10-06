# Cyber Orchestrator

A **local-first orchestration, governance and reporting layer** over the mature
pentest / OSINT / threat-defense toolchain (nmap, aircrack-ng, Suricata, …).
It does **not** reimplement those tools — it launches them in a guided, audited,
scope-enforced way and unifies their output into findings, MITRE ATT&CK mapping
and consulting-grade reports.

> **Authorized use only.** This platform is for a professional security
> engineer performing **explicitly authorized** testing, on a dedicated
> isolated lab VM. Its legal guardrails are blocking controls, not decoration.

## Legal & ethical guardrails (implemented first, non-bypassable)

1. **Mandatory scope declaration.** Before any active/offensive action, the
   engagement must carry an **accepted, time-boxed authorization**: written
   mandate reference, authorizing party, target perimeter (IP/CIDR/host/SSID),
   validity window. (`POST /api/engagements/{id}/authorization`)
2. **Software blocking, not warnings.** Every run passes through one chokepoint
   (`orchestrator.launch`) → `security/scope.check`. Out-of-scope target,
   expired window, missing authorization, or the offensive kill-switch →
   the run is **refused** with `status=blocked`. See the tests.
3. **Immutable audit log.** Every action is recorded in an append-only,
   **hash-chained** log (`security/audit.py`) with a second on-disk copy.
   `GET /api/audit/verify` walks the chain and detects any tampering.
4. **Authorization stated in every report.** Cover page + a dedicated legal
   section carry perimeter, mandate, authorizing party, dates and author.

## Quickstart

```bash
cd cyber-orchestrator/backend
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m app                      # serves 127.0.0.1:8777 (loopback only)
# open http://127.0.0.1:8777/      API docs at /docs
```

Full VM setup (Debian 12 / Kali), including the wrapped CLI tools and optional
Docker for containerised tools:

```bash
sudo cyber-orchestrator/provisioning/provision.sh --minimal          # core + nmap
sudo cyber-orchestrator/provisioning/provision.sh --with-containers  # + Docker tools
```

> Tools that aren't installed run in clearly-flagged **simulation mode**, so the
> full workflow (wizard → scope guard → audit → findings → report) is testable
> immediately, even before the toolchain is provisioned.

## Using it

1. **Create an engagement** (Attack or Defense mode).
2. **Declare scope** (Attack): mandate ref, authorizing party, targets, dates.
3. Pick a **module** from the category sidebar → follow the **step-by-step
   assistant** (progress bar, contextual help, "what to expect", Back/Next).
4. **Launch.** The scope guard + audit run first; then findings appear with
   their **live MITRE ATT&CK mapping** in the right panel.
5. **Generate a report** (themed HTML, PDF when WeasyPrint is installed) from
   the report library.

## Shipped example modules (the validated pattern)

- **Attack — `nmap_scan`** (Network scan, *active*, T1046/T1018): guided port/
  service discovery, XML parsing → per-port findings, risky-service escalation.
- **Defense — `log_analysis`** (Log analysis, *passive*, T1110.001/T1078):
  sshd brute-force & suspicious-success detection with prioritized remediation.

Both follow the same `BasePlugin` contract — duplicate it for the catalog in
[`docs/TOOLS_CATALOG.md`](docs/TOOLS_CATALOG.md).

## Project structure

```
cyber-orchestrator/
├── README.md
├── docs/
│   ├── ARCHITECTURE.md        # component diagram + data flow
│   └── TOOLS_CATALOG.md       # ecosystem + integration mode per tool
├── provisioning/
│   └── provision.sh           # Debian/Kali VM setup (deps, tools, privileges)
├── frontend/
│   └── index.html             # local SPA: attack/defense tabs, wizard, MITRE, reports
└── backend/
    ├── requirements.txt
    ├── .env.example
    ├── app/
    │   ├── main.py            # FastAPI app (loopback), serves the SPA
    │   ├── config.py          # settings, safety switches
    │   ├── database.py models.py schemas.py
    │   ├── orchestrator.py    # the single execution chokepoint
    │   ├── mitre.py updater.py
    │   ├── security/
    │   │   ├── scope.py        # BLOCKING scope guard
    │   │   └── audit.py        # hash-chained immutable audit log
    │   ├── plugins/
    │   │   ├── base.py registry.py
    │   │   ├── attack/nmap_scan.py
    │   │   └── defense/log_analysis.py
    │   ├── routers/           # engagements, plugins, runs, audit, reports, updates
    │   └── reporting/
    │       ├── generator.py
    │       └── templates/     # _base.html + attack.html + defense.html themes
    └── tests/test_core.py     # guardrail + plugin + report tests
```

## Stack

FastAPI · SQLAlchemy · SQLite/PostgreSQL · Jinja2 + WeasyPrint · APScheduler
(long scans) · Docker SDK (containerised tools) · vanilla-JS local SPA
(production path: React + Tailwind + websockets).

## Deliverables map (to the design brief)

| Brief | Where |
|-------|-------|
| Architecture (components + data flow) | `docs/ARCHITECTURE.md` |
| Project structure | this README + tree above |
| Core: API, plugin system, DB, legal guardrails | `app/` (`orchestrator`, `plugins/`, `models`, `security/`) |
| End-to-end Attack module | `app/plugins/attack/nmap_scan.py` |
| End-to-end Defense module | `app/plugins/defense/log_analysis.py` |
| Report templates (both themes) | `app/reporting/templates/` |
| VM provisioning script | `provisioning/provision.sh` |
| Tool-integration analysis | `docs/TOOLS_CATALOG.md` |

## Tests

```bash
cd backend && python -m pytest -q
```
Covers: scope blocks without authorization and out-of-perimeter; defense
detection; mode-mismatch rejection; audit-chain integrity; report generation
with authorization text.

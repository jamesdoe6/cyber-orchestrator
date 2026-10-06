# Architecture

Cyber Orchestrator is a **local orchestration layer** over the mature pentest /
defense toolchain. It never reimplements tools (nmap, aircrack-ng, …); it
launches them in a guided, audited, scope-enforced way and unifies their output
into findings, ATT&CK mapping and reports.

## Design principles

1. **Local-first.** API binds to `127.0.0.1` only. No cloud dependency. The
   frontend ships as a single static page served by the backend.
2. **Guardrails are blocking, not advisory.** Every execution passes through
   one chokepoint (`orchestrator.launch`) that enforces scope and writes the
   immutable audit log *before* a tool starts.
3. **Everything is a plugin.** The core speaks one interface; tools drop in
   without touching the engine.
4. **Fail safe.** No authorization → active/offensive actions are refused. The
   offensive kill-switch (`CO_OFFENSIVE_ENABLED=false`) disables all offensive
   plugins globally.

## Component diagram

```
                         ┌───────────────────────────────────────────┐
                         │  Frontend (local SPA, served at 127.0.0.1) │
                         │  Attack tab (red) │ Defense tab (blue)      │
                         │  wizard · MITRE panel · scope · reports     │
                         └───────────────────────┬─────────────────────┘
                                                 │ HTTP (loopback)
┌────────────────────────────────────────────────▼──────────────────────────┐
│ FastAPI backend (app/)                                                      │
│                                                                             │
│  routers/  engagements · plugins · runs · audit · reports                   │
│                                 │                                           │
│                                 ▼                                           │
│                 ┌──────────────────────────────┐                           │
│   runs ───────► │   orchestrator.launch()      │  ◄── single chokepoint     │
│                 │                              │                           │
│                 │  1 validate params           │                           │
│                 │  2 SCOPE GUARD (security/scope) ─── block out-of-scope    │
│                 │  3 AUDIT record (security/audit, hash-chained)            │
│                 │  4 execute via ToolRunner (subprocess / python / sim)     │
│                 │  5 plugin.parse + plugin.findings                         │
│                 │  6 persist Run + Findings                                 │
│                 │  7 AUDIT complete                                         │
│                 └───────┬──────────────┬───────────────┬──────────────────┘ │
│                         │              │               │                    │
│                    plugins/       security/        reporting/               │
│              attack/ · defense/   scope · audit   Jinja2 → HTML/PDF          │
│              (BasePlugin impls)                   (themed per mode)          │
│                         │                                                   │
│                   mitre.py (ATT&CK lookup)                                  │
│                                                                             │
│  database.py / models.py  ── SQLAlchemy ── SQLite (default) or PostgreSQL   │
└──────────────────┬───────────────────────────────────┬─────────────────────┘
                   │ subprocess (argv, never shell)      │ Docker SDK (optional)
          ┌────────▼─────────┐                 ┌─────────▼──────────┐
          │ Host CLI tools    │                 │ Containerised tools │
          │ nmap, aircrack-ng,│                 │ OpenVAS, Metasploit,│
          │ hydra, john …     │                 │ Wazuh, Suricata …   │
          │ (wifi = host, needs│                 │ (isolated/updatable)│
          │  monitor mode)    │                 └────────────────────┘
          └───────────────────┘
```

## Data flow for one guided action

```
operator → wizard collects params → POST /engagements/{id}/runs
   → orchestrator.launch
       → scope.check(privilege, target)         # passive | active | offensive
            ├─ denied  → Run(status=blocked) + audit "run.blocked"  ⟶ STOP
            └─ allowed → audit "run.launch"
       → ToolRunner: real binary | pure-python | simulated (binary absent)
       → plugin.parse(raw) → structured dict
       → plugin.findings(parsed) → Finding rows (severity, CVSS, ATT&CK, remediation)
       → audit "run.complete"
   → UI renders findings + live ATT&CK mapping
   → POST /engagements/{id}/report → Jinja2 themed HTML (+ WeasyPrint PDF)
```

## Privilege levels (scope enforcement)

| Level       | Meaning                                   | Needs authorization? |
|-------------|-------------------------------------------|----------------------|
| `passive`   | no packets to target (OSINT, log parsing) | no (still audited)   |
| `active`    | touches target, non-destructive (scan)    | yes, target in scope |
| `offensive` | exploitation / creds / injection / wifi   | yes + kill-switch on |

## Isolation model (VM vs containers)

- The **core app + wifi tooling** run directly on the VM — wifi needs a real
  interface in monitor/injection mode, which a container cannot have cleanly.
- **Heavy / independently-updated tools** (OpenVAS, Metasploit, Wazuh,
  Suricata, MISP, BloodHound+Neo4j) run as **Docker containers inside the VM**,
  launched on demand via the Docker SDK. This keeps their dependencies and
  update cadence separate from the core.

## Extending: add a plugin

Create `app/plugins/attack/<tool>.py` (or `defense/`) with a `BasePlugin`
subclass: set `meta` (slug, mode, category, privilege, ATT&CK, wizard `steps`,
`params`), and implement `build_argv`/`execute_python`, `parse`, `findings`.
The registry auto-discovers it; the UI, scope guard, audit and reporting work
with no core changes.

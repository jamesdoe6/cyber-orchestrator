"""Central configuration.

Everything is local-first: the API binds to loopback only, the database
defaults to a file-backed SQLite store, and no outbound traffic happens
unless the operator configures the update module or an external-API plugin
(Shodan, Censys, ...) with their own keys.
"""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent          # .../backend
DATA_DIR = BASE_DIR / "var"                                # runtime data
REPORT_DIR = DATA_DIR / "reports"
AUDIT_DIR = DATA_DIR / "audit"

for _d in (DATA_DIR, REPORT_DIR, AUDIT_DIR):
    _d.mkdir(parents=True, exist_ok=True)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CO_", env_file=".env", extra="ignore")

    # --- Networking (loopback only by default — never expose this) ---
    host: str = "127.0.0.1"
    port: int = 8777

    # --- Persistence ---
    # Postgres example: postgresql+psycopg://user:pass@127.0.0.1/cyberorch
    database_url: str = f"sqlite:///{DATA_DIR / 'cyberorch.db'}"

    # --- Safety switches ---
    # Hard kill-switch for every offensive plugin. When false, only defensive
    # and passive-recon plugins may run, regardless of scope authorization.
    offensive_enabled: bool = True
    # Require an active, in-window authorization before ANY plugin whose
    # privilege level is >= "active" can launch. Leave this on in production.
    enforce_scope: bool = True

    # --- External feeds for the update module (operator-supplied) ---
    mitre_attack_stix_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack.json"
    )
    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str | None = None

    # --- Reporting ---
    report_author: str = "Security Engineer"
    report_org: str = "Independent Assessment"

    paths_data: Path = DATA_DIR
    paths_reports: Path = REPORT_DIR
    paths_audit: Path = AUDIT_DIR


settings = Settings()

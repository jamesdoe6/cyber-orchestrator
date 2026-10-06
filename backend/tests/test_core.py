"""End-to-end tests for the guardrails, plugin pattern and reporting."""
from datetime import datetime, timedelta, timezone


def _authorize(client, eid, cidr="192.0.2.0/24", accept=True, days=1):
    now = datetime.now(timezone.utc)
    return client.post(f"/api/engagements/{eid}/authorization", json={
        "authorization_ref": "MANDATE-TEST-001",
        "authorizing_party": "Test CISO",
        "targets": [{"type": "cidr", "value": cidr}],
        "valid_from": (now - timedelta(hours=1)).isoformat(),
        "valid_until": (now + timedelta(days=days)).isoformat(),
        "accept": accept,
    })


def test_health_and_plugins(client):
    assert client.get("/api/health").json()["status"] == "ok"
    slugs = {p["slug"] for p in client.get("/api/plugins").json()["plugins"]}
    assert {"nmap_scan", "log_analysis"} <= slugs


def test_defense_log_analysis_detects_bruteforce(client):
    e = client.post("/api/engagements", json={"name": "d", "mode": "defense", "operator": "t"}).json()
    r = client.post(f"/api/engagements/{e['id']}/runs",
                    json={"plugin": "log_analysis", "params": {"bruteforce_threshold": 5}}).json()
    assert r["status"] == "completed"
    sevs = {f["severity"] for f in r["findings"]}
    assert "critical" in sevs  # brute force followed by a successful login


def test_scope_blocks_without_authorization(client):
    e = client.post("/api/engagements", json={"name": "a", "mode": "attack", "operator": "t"}).json()
    r = client.post(f"/api/engagements/{e['id']}/runs",
                    json={"plugin": "nmap_scan", "params": {"target": "192.0.2.10"}}).json()
    assert r["status"] == "blocked"
    assert "no_authorization" in r["error"]


def test_scope_blocks_out_of_perimeter(client):
    e = client.post("/api/engagements", json={"name": "a", "mode": "attack", "operator": "t"}).json()
    _authorize(client, e["id"])
    allowed = client.post(f"/api/engagements/{e['id']}/runs",
                          json={"plugin": "nmap_scan", "params": {"target": "192.0.2.50"}}).json()
    assert allowed["status"] == "completed"
    blocked = client.post(f"/api/engagements/{e['id']}/runs",
                          json={"plugin": "nmap_scan", "params": {"target": "10.0.0.1"}}).json()
    assert blocked["status"] == "blocked"
    assert "out_of_scope" in blocked["error"]


def test_mode_mismatch_rejected(client):
    e = client.post("/api/engagements", json={"name": "d", "mode": "defense", "operator": "t"}).json()
    resp = client.post(f"/api/engagements/{e['id']}/runs",
                       json={"plugin": "nmap_scan", "params": {"target": "192.0.2.10"}})
    assert resp.status_code == 400


def test_audit_chain_integrity(client):
    e = client.post("/api/engagements", json={"name": "a", "mode": "attack", "operator": "t"}).json()
    _authorize(client, e["id"])
    client.post(f"/api/engagements/{e['id']}/runs",
                json={"plugin": "nmap_scan", "params": {"target": "192.0.2.10"}})
    assert client.get("/api/audit/verify").json()["valid"] is True


def test_report_generation_includes_authorization(client):
    e = client.post("/api/engagements", json={"name": "RptTest", "mode": "attack", "operator": "t"}).json()
    _authorize(client, e["id"])
    client.post(f"/api/engagements/{e['id']}/runs",
                json={"plugin": "nmap_scan", "params": {"target": "192.0.2.10"}})
    rep = client.post(f"/api/engagements/{e['id']}/report").json()
    assert rep["html_path"]
    html = open(rep["html_path"], encoding="utf-8").read()
    assert "MANDATE-TEST-001" in html and "Offensive" in html

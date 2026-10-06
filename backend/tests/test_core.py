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
    r = client.post(f"/api/engagements/{e['id']}/runs?wait=true",
                    json={"plugin": "log_analysis", "params": {"bruteforce_threshold": 5}}).json()
    assert r["status"] == "completed"
    sevs = {f["severity"] for f in r["findings"]}
    assert "critical" in sevs  # brute force followed by a successful login


def test_scope_blocks_without_authorization(client):
    e = client.post("/api/engagements", json={"name": "a", "mode": "attack", "operator": "t"}).json()
    r = client.post(f"/api/engagements/{e['id']}/runs?wait=true",
                    json={"plugin": "nmap_scan", "params": {"target": "192.0.2.10"}}).json()
    assert r["status"] == "blocked"
    assert "no_authorization" in r["error"]


def test_scope_blocks_out_of_perimeter(client):
    e = client.post("/api/engagements", json={"name": "a", "mode": "attack", "operator": "t"}).json()
    _authorize(client, e["id"])
    allowed = client.post(f"/api/engagements/{e['id']}/runs?wait=true",
                          json={"plugin": "nmap_scan", "params": {"target": "192.0.2.50"}}).json()
    assert allowed["status"] == "completed"
    blocked = client.post(f"/api/engagements/{e['id']}/runs?wait=true",
                          json={"plugin": "nmap_scan", "params": {"target": "10.0.0.1"}}).json()
    assert blocked["status"] == "blocked"
    assert "out_of_scope" in blocked["error"]


def test_mode_mismatch_rejected(client):
    e = client.post("/api/engagements", json={"name": "d", "mode": "defense", "operator": "t"}).json()
    resp = client.post(f"/api/engagements/{e['id']}/runs?wait=true",
                       json={"plugin": "nmap_scan", "params": {"target": "192.0.2.10"}})
    assert resp.status_code == 400


def test_audit_chain_integrity(client):
    e = client.post("/api/engagements", json={"name": "a", "mode": "attack", "operator": "t"}).json()
    _authorize(client, e["id"])
    client.post(f"/api/engagements/{e['id']}/runs?wait=true",
                json={"plugin": "nmap_scan", "params": {"target": "192.0.2.10"}})
    assert client.get("/api/audit/verify").json()["valid"] is True


def test_report_generation_includes_authorization(client):
    e = client.post("/api/engagements", json={"name": "RptTest", "mode": "attack", "operator": "t"}).json()
    _authorize(client, e["id"])
    client.post(f"/api/engagements/{e['id']}/runs?wait=true",
                json={"plugin": "nmap_scan", "params": {"target": "192.0.2.10"}})
    rep = client.post(f"/api/engagements/{e['id']}/report").json()
    assert rep["html_path"]
    html = open(rep["html_path"], encoding="utf-8").read()
    assert "MANDATE-TEST-001" in html and "Offensive" in html


def test_revoke_scope(client):
    e = client.post("/api/engagements", json={"name": "r", "mode": "attack", "operator": "t"}).json()
    _authorize(client, e["id"])
    assert client.get(f"/api/engagements/{e['id']}").json()["has_authorization"] is True
    assert client.request("DELETE", f"/api/engagements/{e['id']}/authorization").json()["ok"] is True
    assert client.get(f"/api/engagements/{e['id']}").json()["has_authorization"] is False
    # offensive/active now blocked again
    r = client.post(f"/api/engagements/{e['id']}/runs?wait=true",
                    json={"plugin": "nmap_scan", "params": {"target": "192.0.2.10"}}).json()
    assert r["status"] == "blocked"


def test_delete_engagement_keeps_audit(client):
    e = client.post("/api/engagements", json={"name": "d", "mode": "defense", "operator": "t"}).json()
    client.post(f"/api/engagements/{e['id']}/runs?wait=true", json={"plugin": "log_analysis", "params": {}})
    assert client.request("DELETE", f"/api/engagements/{e['id']}").json()["ok"] is True
    assert client.get(f"/api/engagements/{e['id']}").status_code == 404
    # immutable audit chain stays intact after deletion
    assert client.get("/api/audit/verify").json()["valid"] is True


def test_background_run_and_websocket(client):
    e = client.post("/api/engagements", json={"name": "ws", "mode": "attack", "operator": "t"}).json()
    _authorize(client, e["id"])
    with client.websocket_connect(f"/ws/engagements/{e['id']}") as ws:
        assert ws.receive_json()["type"] == "hello"
        r = client.post(f"/api/engagements/{e['id']}/runs",
                        json={"plugin": "nmap_scan", "params": {"target": "192.0.2.10"}}).json()
        assert r["status"] == "pending"            # returns immediately (background)
        types = []
        for _ in range(80):
            ev = ws.receive_json()
            types.append(ev["type"])
            if ev["type"] == "done":
                assert ev["status"] == "completed"
                break
        assert "status" in types and "line" in types and "done" in types


def test_concurrent_runs_keep_audit_intact(client):
    import time
    e = client.post("/api/engagements", json={"name": "c", "mode": "attack", "operator": "t"}).json()
    _authorize(client, e["id"])
    ids = [client.post(f"/api/engagements/{e['id']}/runs",
                       json={"plugin": "nmap_scan", "params": {"target": "192.0.2.10"}}).json()["id"]
           for _ in range(10)]
    deadline = time.time() + 20
    runs = {}
    while time.time() < deadline:
        runs = {r["id"]: r["status"] for r in client.get(f"/api/engagements/{e['id']}/runs").json()}
        if all(runs.get(i) in ("completed", "failed", "blocked") for i in ids):
            break
        time.sleep(0.2)
    assert all(runs.get(i) == "completed" for i in ids)
    assert client.get("/api/audit/verify").json()["valid"] is True


def _register_sleep_plugin():
    from app.models import Mode
    from app.plugins import registry
    from app.plugins.base import BasePlugin, PluginMeta, Param, Step

    class SleepPlugin(BasePlugin):
        meta = PluginMeta(slug="_sleep_test", name="sleep", mode=Mode.attack,
                          category="Network scan", privilege="active", binary="sleep", description="test",
                          attack_techniques=["T1046"],
                          params=[Param("target", "Target", "string")],
                          steps=[Step("s", "1", "h", ["target"], "")])
        def build_argv(self, p):  # ignores target; just a long-running process
            return ["sleep", "30"]
        def simulate(self, p):
            return "sim"
        def parse(self, raw, p):
            return {}
        def findings(self, parsed, p):
            return []
    registry._REGISTRY["_sleep_test"] = SleepPlugin()


def test_cancel_running_scan(client):
    import time
    _register_sleep_plugin()
    e = client.post("/api/engagements", json={"name": "cx", "mode": "attack", "operator": "t"}).json()
    _authorize(client, e["id"])
    r = client.post(f"/api/engagements/{e['id']}/runs",
                    json={"plugin": "_sleep_test", "params": {"target": "192.0.2.10"}}).json()
    assert r["status"] == "pending"
    # wait until it is actually running
    for _ in range(40):
        st = client.get(f"/api/engagements/{e['id']}/runs/{r['id']}").json()["status"]
        if st == "running":
            break
        time.sleep(0.1)
    resp = client.post(f"/api/engagements/{e['id']}/runs/{r['id']}/cancel").json()
    assert resp["ok"] and resp["status"] in ("cancelling", "cancelled")
    # it should finalize as cancelled quickly (not wait out sleep 30)
    start = time.time()
    final = None
    while time.time() - start < 8:
        final = client.get(f"/api/engagements/{e['id']}/runs/{r['id']}").json()["status"]
        if final == "cancelled":
            break
        time.sleep(0.2)
    assert final == "cancelled"
    assert client.get("/api/audit/verify").json()["valid"] is True


def test_cancel_queued_run(client):
    # prepare() creates a pending run without dispatching it; cancel must flip it.
    from app import orchestrator
    from app.database import SessionLocal
    from app.models import Engagement
    from app.plugins import registry
    e = client.post("/api/engagements", json={"name": "cq", "mode": "attack", "operator": "t"}).json()
    _authorize(client, e["id"])
    db = SessionLocal()
    run = orchestrator.prepare(db, engagement=db.get(Engagement, e["id"]),
                               plugin=registry.get("nmap_scan"),
                               params={"target": "192.0.2.10"}, actor="t")
    rid = run.id
    db.close()
    resp = client.post(f"/api/engagements/{e['id']}/runs/{rid}/cancel").json()
    assert resp["status"] == "cancelled"
    assert client.get(f"/api/engagements/{e['id']}/runs/{rid}").json()["status"] == "cancelled"

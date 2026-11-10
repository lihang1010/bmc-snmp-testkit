"""Read-only Web service end-to-end tests (local mock agent only)."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from snmp_test.service.app import create_app

ROOT = Path(__file__).resolve().parents[1]
MIB_BYTES = (ROOT / "TTY-T1ZDG-v1.0_20261026.mib").read_bytes()

OPERATOR = "operator-token-xyz"
VIEWER = "viewer-token-xyz"
ADMIN = "admin-token-xyz"


def _web_yaml(allow_live: bool = False, allowed: str = "") -> str:
    lines = [
        "auth:",
        "  users:",
        f"    - {{name: alice, token: {OPERATOR}, role: operator}}",
        f"    - {{name: bob, token: {VIEWER}, role: viewer}}",
        f"    - {{name: root, token: {ADMIN}, role: admin}}",
        "security:",
        f"  allow_live: {'true' if allow_live else 'false'}",
        "  allowed_targets:",
    ]
    if allowed:
        lines.append(f"    - {allowed}")
    return "\n".join(lines) + "\n"


def _make_app(root: Path, allow_live: bool = False, allowed: str = ""):
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "config" / "web.yaml").write_text(_web_yaml(allow_live, allowed), encoding="utf-8")
    shutil.copy(ROOT / "config" / "safety-policy.yaml", root / "config" / "safety-policy.yaml")
    return create_app(root=root, config_path=root / "config" / "web.yaml")


def _headers(token: str = OPERATOR) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _wait_done(client: TestClient, job_id: str, timeout: float = 40.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/api/jobs/{job_id}", headers=_headers())
        assert r.status_code == 200
        job = r.json()
        if job["status"] in ("done", "failed"):
            return job
        time.sleep(0.25)
    raise AssertionError("job did not finish in time")


@pytest.fixture(scope="module")
def web(tmp_path_factory):
    root = tmp_path_factory.mktemp("webroot")
    app = _make_app(root)
    with TestClient(app) as client:
        yield client, root, app


def test_health_and_authentication(web):
    client, _, _ = web
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/api/mibs").status_code == 401
    assert client.get("/api/mibs", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/mibs", headers=_headers(VIEWER)).status_code == 200
    r = client.post("/api/session", json={"token": OPERATOR})
    assert r.status_code == 200 and r.json()["user"] == "alice"
    assert client.get("/api/mibs").status_code == 200  # cookie session


def test_viewer_cannot_write(web):
    client, _, _ = web
    assert client.post("/api/mibs", content=MIB_BYTES[:100], headers=_headers(VIEWER)).status_code == 403


def test_upload_isolation_and_dedup(web):
    client, root, _ = web
    headers = {**_headers(), "X-MIB-Filename": "project-a.mib", "Content-Type": "application/octet-stream"}
    r1 = client.post("/api/mibs", content=MIB_BYTES, headers=headers)
    assert r1.status_code == 200, r1.text
    m1 = r1.json()["mib"]
    assert m1["node_count"] > 1000 and m1["case_count"] > 1000

    r2 = client.post("/api/mibs", content=MIB_BYTES, headers=headers)
    assert r2.json()["mib"]["mib_id"] == m1["mib_id"], "identical content must deduplicate"

    variant = MIB_BYTES + b"\n-- project-b marker\n"
    headers2 = {**headers, "X-MIB-Filename": "project-b.mib"}
    r3 = client.post("/api/mibs", content=variant, headers=headers2)
    assert r3.status_code == 200, r3.text
    m2 = r3.json()["mib"]
    assert m2["mib_id"] != m1["mib_id"]
    assert (root / "work" / "mibs" / m1["mib_id"] / "cases.json").is_file()
    assert (root / "work" / "mibs" / m2["mib_id"] / "cases.json").is_file()
    ids1 = {c["case_id"] for c in json.loads((root / "work" / "mibs" / m1["mib_id"] / "cases.json").read_text(encoding="utf-8"))["cases"]}
    ids2 = {c["case_id"] for c in json.loads((root / "work" / "mibs" / m2["mib_id"] / "cases.json").read_text(encoding="utf-8"))["cases"]}
    assert not (ids1 & ids2), "case ids must be scoped to their own MIB hash"

    bad = client.post("/api/mibs", content=b"not a mib", headers=headers)
    assert bad.status_code == 400
    assert client.get("/api/mibs/does-not-exist", headers=_headers()).status_code == 404


def test_readonly_job_end_to_end(web):
    client, root, app = web
    mibs = client.get("/api/mibs", headers=_headers()).json()["mibs"]
    mib_id = mibs[0]["mib_id"]
    payload = {
        "mib_id": mib_id, "mode": "mock", "target_host": "127.0.0.1",
        "target_port": 11811, "version": "v1", "limit": 6,
        "modules": [], "credential": {"community": "never-store-this-secret"},
    }
    r = client.post("/api/jobs", json=payload, headers=_headers())
    assert r.status_code == 200, r.text
    job_id = r.json()["job"]["job_id"]
    job = _wait_done(client, job_id)
    assert job["status"] == "done", job["message"]
    assert job["case_count"] == 6
    assert job["summary"]["failed"] == 0 and job["summary"]["error"] == 0
    assert job["summary"]["effective_pass_rate"] == 100.0

    run_id = job["run_id"]
    html = client.get(f"/runs/{run_id}/report.html", headers=_headers())
    assert html.status_code == 200 and "BMC SNMP" in html.text
    results = client.get(f"/runs/{run_id}/results.json", headers=_headers()).json()
    assert {x["operation"] for x in results["results"]} == {"GET"}
    # A client without a cookie/header must not be able to read the report.
    assert TestClient(app).get(f"/runs/{run_id}/report.html").status_code == 401
    assert client.get("/api/runs/not-a-run/files", headers=_headers()).status_code == 404

    pdu_log = root / "runs" / run_id / "pdus.jsonl"
    ops = {json.loads(line)["operation"] for line in pdu_log.read_text(encoding="utf-8").splitlines() if line.strip()}
    assert ops == {"GET"}, "no SET/other operation may be emitted by the service"

    # credentials must never reach any persisted artefact
    for path in (root / "work" / "jobs").rglob("*.jsonl"):
        assert "never-store-this-secret" not in path.read_text(encoding="utf-8")
    snapshot = (root / "runs" / run_id / "config-snapshot.yaml").read_text(encoding="utf-8")
    assert "never-store-this-secret" not in snapshot


def test_live_is_denied_by_default(web):
    client, _, _ = web
    mib_id = client.get("/api/mibs", headers=_headers()).json()["mibs"][0]["mib_id"]
    payload = {"mib_id": mib_id, "mode": "live", "target_host": "192.0.2.10",
               "target_port": 161, "version": "v1", "limit": 5}
    assert client.post("/api/jobs", json=payload, headers=_headers(OPERATOR)).status_code == 403
    assert client.post("/api/jobs", json=payload, headers=_headers(ADMIN)).status_code == 403
    assert client.get("/api/config", headers=_headers()).json()["live_enabled"] is False


def test_live_allowlist_is_enforced(tmp_path):
    root = tmp_path / "allowlist"
    app = _make_app(root, allow_live=True, allowed="192.0.2.1")
    with TestClient(app) as client:
        assert client.get("/api/config", headers=_headers()).json()["allowed_targets"] == ["192.0.2.1"]
        uploaded = client.post(
            "/api/mibs", content=MIB_BYTES,
            headers={**_headers(), "X-MIB-Filename": "a.mib"},
        ).json()["mib"]["mib_id"]
        payload = {"mib_id": uploaded, "mode": "live", "target_host": "10.0.0.99",
                   "target_port": 161, "version": "v1", "limit": 5}
        assert client.post("/api/jobs", json=payload, headers=_headers(ADMIN)).status_code == 403
        payload["target_host"] = "203.0.113.5"
        assert client.post("/api/jobs", json=payload, headers=_headers(VIEWER)).status_code == 403


def test_index_page_and_capabilities(web):
    client, _, _ = web
    page = client.get("/")
    assert page.status_code == 200 and "上传项目 MIB" in page.text
    cap = client.get("/api/config", headers=_headers()).json()
    assert cap["readonly_only"] is True
    assert cap["allowed_operations"] == ["GET"]
    assert cap["mib_count"] >= 2

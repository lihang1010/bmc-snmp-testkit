"""Read-only Web service end-to-end tests (email accounts + local mock agent)."""

from __future__ import annotations

import json
import os
import shutil
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from snmp_test.service.app import COOKIE, create_app

ROOT = Path(__file__).resolve().parents[1]
MIB_BYTES = (ROOT / "TTY-T1ZDG-v1.0_20261026.mib").read_bytes()

ALICE = "alice@example.com"
BOB = "bob@example.com"
PASSWORD = "test-password-123"


def _web_yaml(allow_live: bool = False, allowed: str = "") -> str:
    lines = [
        "security:",
        f"  allow_live: {'true' if allow_live else 'false'}",
        "  allowed_targets:",
    ]
    if allowed:
        lines.append(f"    - {allowed}")
    return "\n".join(lines) + "\n"


def _make_app(root: Path, allow_live: bool = False, allowed: str = "", clear_bypass: bool = True):
    if clear_bypass:
        os.environ.pop("SNMP_TEST_DEV_BYPASS", None)
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "config" / "web.yaml").write_text(_web_yaml(allow_live, allowed), encoding="utf-8")
    shutil.copy(ROOT / "config" / "safety-policy.yaml", root / "config" / "safety-policy.yaml")
    return create_app(root=root, config_path=root / "config" / "web.yaml")


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@contextmanager
def _no_cookie(client: TestClient):
    """Temporarily drop the client's session cookie to simulate an anonymous visitor.

    Reusing one TestClient avoids starting a second lifespan/worker on the same app.
    """
    jar = client.cookies.jar
    saved = list(jar)
    jar.clear()
    try:
        yield client
    finally:
        for cookie in saved:
            jar.set_cookie(cookie)


def _send_code(client: TestClient, email: str, purpose: str) -> str:
    r = client.post("/api/auth/code", json={"email": email, "purpose": purpose})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sent"] is False and body["dev_code"], "tests run in dev mail mode"
    return body["dev_code"]


def _register(client: TestClient, email: str, password: str = PASSWORD) -> str:
    code = _send_code(client, email, "register")
    r = client.post("/api/auth/register", json={"email": email, "code": code, "password": password})
    assert r.status_code == 200, r.text
    token = r.cookies.get(COOKIE)
    assert token, "register must set a session cookie"
    return token


def _wait_done(client: TestClient, job_id: str, token: str, timeout: float = 40.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/api/jobs/{job_id}", headers=_headers(token))
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
        alice = _register(client, ALICE)
        bob = _register(client, BOB)
        yield client, root, app, alice, bob


def test_health_and_authentication(web):
    client, _, _, alice, _ = web
    assert client.get("/health").json()["status"] == "ok"
    with _no_cookie(client):
        assert client.get("/api/mibs").status_code == 401
    assert client.get("/api/mibs", headers=_headers("bogus")).status_code == 401
    assert client.get("/api/mibs", headers=_headers(alice)).status_code == 200

    r = client.post("/api/auth/login", json={"email": ALICE, "password": PASSWORD, "method": "password"})
    assert r.status_code == 200 and r.json()["user"] == ALICE

    code = _send_code(client, ALICE, "login")
    r = client.post("/api/auth/login", json={"email": ALICE, "code": code, "method": "code"})
    assert r.status_code == 200 and r.json()["user"] == ALICE


def test_login_page_and_redirect(web):
    client, _, _, alice, _ = web
    with _no_cookie(client):
        page = client.get("/login")
        assert page.status_code == 200 and "密码登录" in page.text
        r = client.get("/", follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"] == "/login"
    assert client.get("/", headers=_headers(alice)).status_code == 200


def test_auth_validation(web):
    client, _, _, alice, _ = web
    assert client.post("/api/auth/code", json={"email": "not-an-email", "purpose": "register"}).status_code == 400
    assert client.post("/api/auth/register", json={"email": ALICE, "code": "000000", "password": PASSWORD}).status_code == 400
    assert client.post("/api/auth/register", json={"email": "new@example.com", "code": "000000", "password": "short"}).status_code == 400
    assert client.post("/api/auth/login", json={"email": BOB, "password": "wrong-password", "method": "password"}).status_code == 401
    assert client.post("/api/auth/code", json={"email": "nobody@example.com", "purpose": "login"}).status_code == 400
    code = _send_code(client, BOB, "login")
    wrong = "000000" if code != "000000" else "111111"
    assert client.post("/api/auth/login", json={"email": BOB, "code": wrong, "method": "code"}).status_code == 401


def test_upload_is_shared_between_accounts(web):
    client, root, _, alice, bob = web
    headers = {**_headers(alice), "X-MIB-Filename": "project-a.mib", "Content-Type": "application/octet-stream"}
    r1 = client.post("/api/mibs", content=MIB_BYTES, headers=headers)
    assert r1.status_code == 200, r1.text
    m1 = r1.json()["mib"]
    assert m1["node_count"] > 1000 and m1["case_count"] > 1000

    r2 = client.post("/api/mibs", content=MIB_BYTES, headers=headers)
    assert r2.json()["mib"]["mib_id"] == m1["mib_id"], "identical content must deduplicate"

    variant = MIB_BYTES + b"\n-- project-b marker\n"
    r3 = client.post("/api/mibs", content=variant, headers={**headers, "X-MIB-Filename": "project-b.mib"})
    assert r3.status_code == 200, r3.text

    # the library is shared: both accounts see the same records
    seen_by_alice = {m["mib_id"] for m in client.get("/api/mibs", headers=_headers(alice)).json()["mibs"]}
    seen_by_bob = {m["mib_id"] for m in client.get("/api/mibs", headers=_headers(bob)).json()["mibs"]}
    assert seen_by_alice == seen_by_bob and m1["mib_id"] in seen_by_bob

    bad = client.post("/api/mibs", content=b"not a mib", headers=headers)
    assert bad.status_code == 400
    assert client.get("/api/mibs/does-not-exist", headers=_headers(alice)).status_code == 404


def test_readonly_job_end_to_end(web):
    client, root, _, alice, bob = web
    mib_id = client.get("/api/mibs", headers=_headers(alice)).json()["mibs"][0]["mib_id"]
    payload = {
        "mib_id": mib_id, "mode": "mock", "target_host": "127.0.0.1",
        "target_port": 11811, "version": "v1", "limit": 6,
        "modules": [], "credential": {"community": "never-store-this-secret"},
    }
    r = client.post("/api/jobs", json=payload, headers=_headers(alice))
    assert r.status_code == 200, r.text
    job_id = r.json()["job"]["job_id"]
    job = _wait_done(client, job_id, alice)
    assert job["status"] == "done", job["message"]
    assert job["case_count"] == 6
    assert job["summary"]["failed"] == 0 and job["summary"]["error"] == 0
    assert job["summary"]["effective_pass_rate"] == 100.0

    run_id = job["run_id"]
    html = client.get(f"/runs/{run_id}/report.html", headers=_headers(alice))
    assert html.status_code == 200 and "BMC SNMP" in html.text
    results = client.get(f"/runs/{run_id}/results.json", headers=_headers(alice)).json()
    assert {x["operation"] for x in results["results"]} == {"GET"}

    # reports are private: another account and an anonymous client must not read them
    assert client.get(f"/runs/{run_id}/report.html", headers=_headers(bob)).status_code == 404
    with _no_cookie(client):
        assert client.get(f"/runs/{run_id}/report.html").status_code == 401
    assert client.get("/api/runs/not-a-run/files", headers=_headers(alice)).status_code == 404

    pdu_log = root / "runs" / run_id / "pdus.jsonl"
    ops = {json.loads(line)["operation"] for line in pdu_log.read_text(encoding="utf-8").splitlines() if line.strip()}
    assert ops == {"GET"}, "no SET/other operation may be emitted by the service"

    for path in (root / "work" / "jobs").rglob("*.jsonl"):
        assert "never-store-this-secret" not in path.read_text(encoding="utf-8")
    snapshot = (root / "runs" / run_id / "config-snapshot.yaml").read_text(encoding="utf-8")
    assert "never-store-this-secret" not in snapshot


def test_job_queue_is_private(web):
    client, _, _, alice, bob = web
    alice_jobs = client.get("/api/jobs", headers=_headers(alice)).json()["jobs"]
    bob_jobs = client.get("/api/jobs", headers=_headers(bob)).json()["jobs"]
    assert alice_jobs and not bob_jobs, "jobs must not leak across accounts"
    assert all(j["user"] == ALICE for j in alice_jobs)
    job_id = alice_jobs[0]["job_id"]
    assert client.get(f"/api/jobs/{job_id}", headers=_headers(bob)).status_code == 404


def test_live_is_denied_by_default(web):
    client, _, _, alice, bob = web
    mib_id = client.get("/api/mibs", headers=_headers(alice)).json()["mibs"][0]["mib_id"]
    payload = {"mib_id": mib_id, "mode": "live", "target_host": "192.0.2.10",
               "target_port": 161, "version": "v1", "limit": 5}
    assert client.post("/api/jobs", json=payload, headers=_headers(alice)).status_code == 403
    assert client.post("/api/jobs", json=payload, headers=_headers(bob)).status_code == 403
    assert client.get("/api/config", headers=_headers(alice)).json()["live_enabled"] is False


def test_live_allowlist_is_enforced(tmp_path):
    root = tmp_path / "allowlist"
    app = _make_app(root, allow_live=True, allowed="192.0.2.1")
    with TestClient(app) as client:
        token = _register(client, "live@example.com")
        assert client.get("/api/config", headers=_headers(token)).json()["allowed_targets"] == ["192.0.2.1"]
        uploaded = client.post(
            "/api/mibs", content=MIB_BYTES,
            headers={**_headers(token), "X-MIB-Filename": "a.mib"},
        ).json()["mib"]["mib_id"]
        payload = {"mib_id": uploaded, "mode": "live", "target_host": "10.0.0.99",
                   "target_port": 161, "version": "v1", "limit": 5}
        assert client.post("/api/jobs", json=payload, headers=_headers(token)).status_code == 403
        payload["target_host"] = "192.0.2.2"
        assert client.post("/api/jobs", json=payload, headers=_headers(token)).status_code == 403


def test_logout_invalidates_session(web):
    client, _, _, _, _ = web
    token = _register(client, "logout@example.com")
    assert client.get("/api/mibs", headers=_headers(token)).status_code == 200
    assert client.post("/api/auth/logout", headers=_headers(token)).status_code == 200
    assert client.get("/api/mibs", headers=_headers(token)).status_code == 401


def test_dev_bypass_skips_login(tmp_path, monkeypatch):
    monkeypatch.setenv("SNMP_TEST_DEV_BYPASS", "1")
    root = tmp_path / "bypass"
    app = _make_app(root, clear_bypass=False)
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        assert client.get("/api/mibs").status_code == 200
        assert client.get("/api/session").json()["user"] == "dev@localhost"


def test_index_page_and_capabilities(web):
    client, _, _, alice, _ = web
    page = client.get("/", headers=_headers(alice))
    assert page.status_code == 200 and "上传项目 MIB" in page.text
    cap = client.get("/api/config", headers=_headers(alice)).json()
    assert cap["readonly_only"] is True
    assert cap["allowed_operations"] == ["GET"]
    assert cap["mib_count"] >= 2

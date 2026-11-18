from __future__ import annotations

import gc
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import snmp_test.service.auth as auth_module
from snmp_test.service.auth import AuthError, AuthService, Mailer


@pytest.fixture
def connections(monkeypatch):
    opened = []
    connect = sqlite3.connect

    def track(*args, **kwargs):
        conn = connect(*args, **kwargs)
        opened.append(conn)
        return conn

    monkeypatch.setattr(sqlite3, "connect", track)
    yield opened
    for conn in opened:
        conn.close()


def assert_connections_closed(connections):
    assert connections
    for conn in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            conn.execute("SELECT 1")


def test_auth_closes_connections_on_success_and_early_return(tmp_path, connections):
    auth = AuthService(tmp_path / "auth.db", dev_bypass=False)
    assert_connections_closed(connections)
    assert auth.create_user_direct("reader@example.com", "test-password")
    assert not auth.create_user_direct("reader@example.com", "test-password")
    token, user = auth.login_password("reader@example.com", "test-password")
    assert auth.authenticate(token).email == user.email
    assert auth.authenticate("invalid-token") is None
    auth.logout(token)
    assert auth.authenticate(token) is None
    auth.cleanup()
    assert_connections_closed(connections)


def test_auth_closes_connections_on_rejection(tmp_path, connections):
    auth = AuthService(tmp_path / "auth.db", dev_bypass=False)
    assert auth.create_user_direct("reader@example.com", "test-password")
    with pytest.raises(AuthError, match="邮箱或密码错误"):
        auth.login_password("reader@example.com", "wrong-password")
    assert_connections_closed(connections)
    with pytest.raises(AuthError, match="验证码"):
        auth.login_code("reader@example.com", "000000")
    assert_connections_closed(connections)


def test_connection_context_commits_and_rolls_back(tmp_path, connections):
    auth = AuthService(tmp_path / "auth.db", dev_bypass=False)
    with auth._connect() as conn:
        conn.execute("CREATE TABLE transaction_test(value TEXT)")
        conn.execute("INSERT INTO transaction_test VALUES ('committed')")
    assert_connections_closed(connections)
    with pytest.raises(RuntimeError, match="abort"):
        with auth._connect() as conn:
            conn.execute("INSERT INTO transaction_test VALUES ('rolled back')")
            raise RuntimeError("abort")
    assert_connections_closed(connections)
    with auth._connect() as conn:
        rows = conn.execute("SELECT value FROM transaction_test").fetchall()
        assert [row[0] for row in rows] == ["committed"]
    assert_connections_closed(connections)


def test_connection_is_closed_when_setup_fails(tmp_path, monkeypatch):
    auth = AuthService(tmp_path / "auth.db", dev_bypass=False)
    connect = sqlite3.connect
    opened = []

    class SetupFailure(sqlite3.Connection):
        def execute(self, statement, *args, **kwargs):
            if statement == "PRAGMA journal_mode=WAL":
                raise sqlite3.OperationalError("setup failed")
            return super().execute(statement, *args, **kwargs)

    def track(*args, **kwargs):
        conn = connect(*args, factory=SetupFailure, **kwargs)
        opened.append(conn)
        return conn

    monkeypatch.setattr(sqlite3, "connect", track)
    try:
        with pytest.raises(sqlite3.OperationalError, match="setup failed"):
            auth.authenticate("invalid-token")
        assert_connections_closed(opened)
    finally:
        for conn in opened:
            conn.close()


@pytest.mark.skipif(not Path("/proc/self/fd").is_dir(), reason="Linux FD accounting required")
def test_repeated_authentication_does_not_depend_on_garbage_collection(tmp_path):
    auth = AuthService(tmp_path / "auth.db", dev_bypass=False)
    auth.create_user_direct("reader@example.com", "test-password")
    token, _ = auth.login_password("reader@example.com", "test-password")
    gc.collect()
    baseline = len(list(Path("/proc/self/fd").iterdir()))
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(100):
            assert auth.authenticate(token) is not None
            assert auth.authenticate("invalid-token") is None
        assert len(list(Path("/proc/self/fd").iterdir())) <= baseline + 1
    finally:
        if was_enabled:
            gc.enable()
        gc.collect()


def test_password_reset_invalidates_old_sessions(tmp_path):
    auth = AuthService(tmp_path / "auth.db", dev_bypass=False)
    email = "reset@example.com"
    auth.create_user_direct(email, "old-password")
    old_token, _ = auth.login_password(email, "old-password")

    with pytest.raises(AuthError, match="验证码"):
        auth.reset_password(email, "000000", "new-password")
    code = auth.send_code(email, "reset")["dev_code"]
    token, user = auth.reset_password(email, code, "new-password")

    assert user.email == email
    assert auth.authenticate(old_token) is None, "password reset must revoke old sessions"
    assert auth.authenticate(token) is not None
    with pytest.raises(AuthError, match="邮箱或密码错误"):
        auth.login_password(email, "old-password")
    assert auth.login_password(email, "new-password")[1].email == email


def test_password_login_locks_after_repeated_failures(tmp_path, monkeypatch):
    clock = {"now": 1_800_000_000.0}
    fake_time = SimpleNamespace(time=lambda: clock["now"], strftime=time.strftime)
    monkeypatch.setattr(auth_module, "time", fake_time)
    auth = AuthService(tmp_path / "auth.db", dev_bypass=False)
    email = "lock@example.com"
    auth.create_user_direct(email, "correct-password")

    for expected in range(1, auth_module.PASSWORD_MAX_FAILURES):
        with pytest.raises(AuthError, match=f"还可尝试 {auth_module.PASSWORD_MAX_FAILURES - expected} 次"):
            auth.login_password(email, "wrong-password")
    with pytest.raises(AuthError, match="次数过多"):
        auth.login_password(email, "wrong-password")

    with pytest.raises(AuthError, match="次数过多"):
        auth.login_password(email, "correct-password")

    clock["now"] += auth_module.PASSWORD_LOCK_SECONDS + 1
    token, _ = auth.login_password(email, "correct-password")
    assert auth.authenticate(token) is not None


def test_mailer_reads_yaml_and_env_overrides(monkeypatch):
    for name in (
        "SNMP_TEST_SMTP_HOST", "SNMP_TEST_SMTP_PORT", "SNMP_TEST_SMTP_USER",
        "SNMP_TEST_SMTP_PASSWORD", "SNMP_TEST_SMTP_FROM", "SNMP_TEST_SMTP_TLS",
        "SNMP_TEST_SMTP_SSL",
    ):
        monkeypatch.delenv(name, raising=False)

    mailer = Mailer({
        "host": "smtp.lan", "port": 2525, "user": "sender@lan",
        "password": "secret", "sender": "no-reply@lan", "tls": False, "ssl": True,
    })
    assert (mailer.host, mailer.port, mailer.username) == ("smtp.lan", 2525, "sender@lan")
    assert mailer.sender == "no-reply@lan" and mailer.starttls is False and mailer.use_ssl is True

    monkeypatch.setenv("SNMP_TEST_SMTP_HOST", "env.lan")
    monkeypatch.setenv("SNMP_TEST_SMTP_TLS", "1")
    assert Mailer({"host": "smtp.lan", "tls": False}).host == "env.lan"
    assert Mailer({"host": "smtp.lan", "tls": False}).starttls is True


def test_mailer_test_message_requires_configuration(tmp_path, monkeypatch):
    monkeypatch.delenv("SNMP_TEST_SMTP_HOST", raising=False)
    auth = AuthService(tmp_path / "auth.db", dev_bypass=False, mail_settings={})
    with pytest.raises(AuthError, match="未配置 SMTP"):
        auth.mailer.send_test("user@example.com")


def test_mailer_sends_through_smtp_ssl(monkeypatch):
    for name in ("SNMP_TEST_SMTP_HOST", "SNMP_TEST_SMTP_SSL", "SNMP_TEST_SMTP_TLS"):
        monkeypatch.delenv(name, raising=False)
    calls = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=10):
            calls["connect"] = (host, port)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self):
            calls["starttls"] = True

        def login(self, user, password):
            calls["login"] = (user, password)

        def send_message(self, message):
            calls["message"] = message

    monkeypatch.setattr(auth_module.smtplib, "SMTP_SSL", FakeSMTP)
    mailer = Mailer({
        "host": "smtp.test", "port": 465, "user": "sender@test",
        "password": "secret", "sender": "sender@test", "ssl": True, "tls": False,
    })
    mailer.send_test("to@test")
    assert calls["connect"] == ("smtp.test", 465)
    assert calls["login"] == ("sender@test", "secret")
    assert calls["message"]["To"] == "to@test"
    assert "starttls" not in calls

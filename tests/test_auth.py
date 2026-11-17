from __future__ import annotations

import gc
import sqlite3
from pathlib import Path

import pytest

from snmp_test.service.auth import AuthError, AuthService


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

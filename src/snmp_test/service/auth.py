"""Email-based account system for the read-only Web service.

Design notes:
  * accounts are identified by email; every registered account has identical
    capabilities (no roles) -- device safety is still enforced by
    ``security.allow_live`` / ``allowed_targets``, which is not a user role;
  * passwords are stored as PBKDF2-HMAC-SHA256 with a per-user random salt;
  * email codes are 6 digits, valid for 10 minutes, rate-limited per address,
    and locked after a few wrong attempts;
  * sessions are opaque random tokens kept server-side (SQLite) and delivered
    as an HttpOnly cookie;
  * mail is sent through SMTP when configured; otherwise (local development)
    the code is written to ``work/mail-dev.log`` and returned to the page.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Any

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

CODE_TTL_SECONDS = 600
CODE_COOLDOWN_SECONDS = 60
CODE_MAX_ATTEMPTS = 5
CODE_PURPOSES = ("login", "register", "reset")
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_FAILURES = 5
PASSWORD_LOCK_SECONDS = 300
SESSION_TTL_SECONDS = 7 * 24 * 3600
PBKDF2_ROUNDS = 240_000

logger = logging.getLogger(__name__)


class AuthError(ValueError):
    """Validation or credential failure whose message is safe to show users."""


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() not in ("0", "false", "no", "off")


@dataclass(frozen=True)
class User:
    email: str
    created_at: float = 0.0

    @property
    def name(self) -> str:
        return self.email

    @property
    def role(self) -> str:
        return "user"

    def can(self, action: str) -> bool:
        # Every registered account has the same capabilities.
        return True


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS).hex()


class Mailer:
    """SMTP sender configured from ``config/web.yaml`` ``mail`` or env vars.

    Environment variables win, so deployments can inject secrets without
    writing them into the yaml file.
    """

    def __init__(self, settings: dict[str, Any] | None = None) -> None:
        settings = dict(settings or {})

        def pick(env_key: str, setting_key: str, default: Any = "") -> Any:
            value = os.environ.get(env_key)
            return settings.get(setting_key, default) if value in (None, "") else value

        self.host = str(pick("SNMP_TEST_SMTP_HOST", "host", "")).strip()
        self.port = int(pick("SNMP_TEST_SMTP_PORT", "port", 587) or 587)
        self.username = str(pick("SNMP_TEST_SMTP_USER", "user", "")).strip()
        self.password = str(pick("SNMP_TEST_SMTP_PASSWORD", "password", ""))
        self.sender = (
            str(pick("SNMP_TEST_SMTP_FROM", "sender", "")).strip()
            or self.username or "no-reply@localhost"
        )
        self.starttls = _as_bool(pick("SNMP_TEST_SMTP_TLS", "tls", "1"), True)
        self.use_ssl = _as_bool(pick("SNMP_TEST_SMTP_SSL", "ssl", ""), False)
        self.last_error = ""

    @property
    def configured(self) -> bool:
        return bool(self.host)

    def _send(self, to_address: str, subject: str, body: str) -> bool:
        if not self.configured:
            return False
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self.sender
        message["To"] = to_address
        message.set_content(body)
        self.last_error = ""
        server = None
        try:
            if self.use_ssl:
                server = smtplib.SMTP_SSL(self.host, self.port, timeout=10)
            else:
                server = smtplib.SMTP(self.host, self.port, timeout=10)
            if self.starttls and not self.use_ssl:
                server.starttls()
            if self.username:
                server.login(self.username, self.password)
            server.send_message(message)
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            logger.warning("SMTP send to %s failed: %s", to_address, self.last_error)
            return False
        finally:
            if server is not None:
                # A reset while saying QUIT must not turn a delivered message
                # into a reported failure.
                try:
                    server.quit()
                except Exception:
                    try:
                        server.close()
                    except Exception:
                        pass
        return True

    def send_code(self, email: str, code: str, purpose: str) -> bool:
        subject = "bmc-snmp-testkit 注册验证码" if purpose == "register" else "bmc-snmp-testkit 登录验证码"
        if purpose == "reset":
            subject = "bmc-snmp-testkit 重置密码验证码"
        return self._send(
            email,
            subject,
            f"你的验证码是 {code}，{CODE_TTL_SECONDS // 60} 分钟内有效。\n"
            "如果这不是你本人的操作，请忽略本邮件。\n",
        )

    def send_test(self, email: str) -> None:
        if not self.configured:
            raise AuthError("未配置 SMTP：请在 config/web.yaml 填写 mail 段或设置 SNMP_TEST_SMTP_* 环境变量")
        if not self._send(email, "bmc-snmp-testkit SMTP 测试", "这是一封 SMTP 配置测试邮件。\n"):
            detail = f"（{self.last_error}）" if self.last_error else ""
            raise AuthError(f"测试邮件发送失败，请检查 SMTP 地址、端口与凭据{detail}")


class AuthService:
    def __init__(
        self,
        db_path: str | Path,
        *,
        dev_bypass: bool | None = None,
        mail_settings: dict[str, Any] | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.mailer = Mailer(mail_settings)
        self.dev_bypass = _env_flag("SNMP_TEST_DEV_BYPASS") if dev_bypass is None else dev_bypass
        self.dev_mail_log = self.db_path.parent / "mail-dev.log"
        self._init_db()

    # ---------------------------------------------------------------- storage
    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        # SQLite's transaction context does not close the connection.
        with closing(sqlite3.connect(self.db_path, timeout=10)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            with conn:
                yield conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users(
                  email TEXT PRIMARY KEY,
                  password_hash TEXT NOT NULL,
                  salt TEXT NOT NULL,
                  created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS codes(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT NOT NULL,
                  code TEXT NOT NULL,
                  purpose TEXT NOT NULL,
                  expires_at REAL NOT NULL,
                  attempts INTEGER NOT NULL DEFAULT 0,
                  used INTEGER NOT NULL DEFAULT 0,
                  created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions(
                  token TEXT PRIMARY KEY,
                  email TEXT NOT NULL,
                  created_at REAL NOT NULL,
                  expires_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS login_failures(
                  email TEXT PRIMARY KEY,
                  failures INTEGER NOT NULL DEFAULT 0,
                  locked_until REAL NOT NULL DEFAULT 0,
                  updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_codes_email ON codes(email, purpose);
                CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email);
                """
            )

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _norm_email(email: str) -> str:
        value = (email or "").strip().lower()
        if not EMAIL_RE.match(value):
            raise AuthError("请输入有效的邮箱地址")
        return value

    @staticmethod
    def _check_password(password: str) -> None:
        if len(password or "") < PASSWORD_MIN_LENGTH:
            raise AuthError(f"密码至少需要 {PASSWORD_MIN_LENGTH} 位")

    def _new_session(self, conn: sqlite3.Connection, email: str) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        conn.execute(
            "INSERT INTO sessions(token, email, created_at, expires_at) VALUES(?,?,?,?)",
            (token, email, now, now + SESSION_TTL_SECONDS),
        )
        conn.commit()
        return token

    def _verify_code(self, conn: sqlite3.Connection, email: str, code: str, purpose: str) -> None:
        row = conn.execute(
            "SELECT id, code, expires_at, attempts FROM codes "
            "WHERE email=? AND purpose=? AND used=0 ORDER BY id DESC LIMIT 1",
            (email, purpose),
        ).fetchone()
        if row is None:
            raise AuthError("验证码无效或已过期，请重新获取")
        if row["attempts"] >= CODE_MAX_ATTEMPTS:
            raise AuthError("验证码尝试次数过多，请重新获取")
        if time.time() > row["expires_at"]:
            raise AuthError("验证码已过期，请重新获取")
        conn.execute("UPDATE codes SET attempts=attempts+1 WHERE id=?", (row["id"],))
        if not secrets.compare_digest(str(row["code"]), str(code or "").strip()):
            conn.commit()
            raise AuthError("验证码错误")
        conn.execute("UPDATE codes SET used=1 WHERE id=?", (row["id"],))
        conn.commit()

    # ---------------------------------------------------------------- public
    def send_code(self, email: str, purpose: str = "login") -> dict:
        purpose = purpose if purpose in CODE_PURPOSES else "login"
        email = self._norm_email(email)
        now = time.time()
        with self._lock, self._connect() as conn:
            exists = conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone() is not None
            if purpose == "register" and exists:
                raise AuthError("该邮箱已注册，请直接登录")
            if purpose in ("login", "reset") and not exists:
                raise AuthError("该邮箱尚未注册，请先注册")
            last = conn.execute(
                "SELECT created_at FROM codes WHERE email=? AND purpose=? ORDER BY id DESC LIMIT 1",
                (email, purpose),
            ).fetchone()
            if last and now - float(last["created_at"]) < CODE_COOLDOWN_SECONDS:
                wait = int(CODE_COOLDOWN_SECONDS - (now - float(last["created_at"]))) + 1
                raise AuthError(f"发送过于频繁，请 {wait} 秒后再试")
            code = f"{secrets.randbelow(1_000_000):06d}"
            conn.execute(
                "INSERT INTO codes(email, code, purpose, expires_at, attempts, used, created_at) "
                "VALUES(?,?,?,?,0,0,?)",
                (email, code, purpose, now + CODE_TTL_SECONDS, now),
            )
            conn.commit()

        if not self.mailer.configured:
            with self.dev_mail_log.open("a", encoding="utf-8") as fh:
                fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {purpose} {email} code={code}\n")
            return {"sent": False, "dev_code": code, "cooldown": CODE_COOLDOWN_SECONDS}
        if not self.mailer.send_code(email, code, purpose):
            detail = f"（{self.mailer.last_error}）" if self.mailer.last_error else ""
            raise AuthError(f"邮件发送失败，请稍后重试或联系管理员{detail}")
        return {"sent": True, "dev_code": None, "cooldown": CODE_COOLDOWN_SECONDS}

    def register(self, email: str, code: str, password: str) -> tuple[str, User]:
        email = self._norm_email(email)
        self._check_password(password)
        now = time.time()
        with self._lock, self._connect() as conn:
            if conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
                raise AuthError("该邮箱已注册，请直接登录")
            self._verify_code(conn, email, code, "register")
            salt = secrets.token_bytes(16)
            conn.execute(
                "INSERT INTO users(email, password_hash, salt, created_at) VALUES(?,?,?,?)",
                (email, _hash_password(password, salt), salt.hex(), now),
            )
            conn.commit()
            token = self._new_session(conn, email)
        return token, User(email, now)

    def reset_password(self, email: str, code: str, password: str) -> tuple[str, User]:
        email = self._norm_email(email)
        self._check_password(password)
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT created_at FROM users WHERE email=?", (email,)).fetchone()
            if row is None:
                raise AuthError("该邮箱尚未注册，请先注册")
            self._verify_code(conn, email, code, "reset")
            salt = secrets.token_bytes(16)
            conn.execute(
                "UPDATE users SET password_hash=?, salt=? WHERE email=?",
                (_hash_password(password, salt), salt.hex(), email),
            )
            # A reset must invalidate every existing session and clear any lockout.
            conn.execute("DELETE FROM sessions WHERE email=?", (email,))
            conn.execute("DELETE FROM login_failures WHERE email=?", (email,))
            conn.commit()
            token = self._new_session(conn, email)
        return token, User(email, float(row["created_at"]))

    def login_password(self, email: str, password: str) -> tuple[str, User]:
        email = self._norm_email(email)
        now = time.time()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT password_hash, salt, created_at FROM users WHERE email=?", (email,)
            ).fetchone()
            if row is None:
                raise AuthError("邮箱或密码错误")
            failure = conn.execute(
                "SELECT failures, locked_until FROM login_failures WHERE email=?", (email,)
            ).fetchone()
            if failure is not None and float(failure["locked_until"]) > now:
                wait = int(float(failure["locked_until"]) - now) + 1
                raise AuthError(f"密码错误次数过多，请 {wait} 秒后再试")
            digest = _hash_password(password or "", bytes.fromhex(row["salt"]))
            if not secrets.compare_digest(digest, row["password_hash"]):
                count = (int(failure["failures"]) if failure else 0) + 1
                locked_until = now + PASSWORD_LOCK_SECONDS if count >= PASSWORD_MAX_FAILURES else 0.0
                conn.execute(
                    "INSERT INTO login_failures(email, failures, locked_until, updated_at) "
                    "VALUES(?,?,?,?) ON CONFLICT(email) DO UPDATE SET "
                    "failures=excluded.failures, locked_until=excluded.locked_until, "
                    "updated_at=excluded.updated_at",
                    (email, count, locked_until, now),
                )
                conn.commit()
                if count >= PASSWORD_MAX_FAILURES:
                    raise AuthError(
                        f"密码错误次数过多，请 {PASSWORD_LOCK_SECONDS // 60} 分钟后再试"
                    )
                raise AuthError(f"邮箱或密码错误，还可尝试 {PASSWORD_MAX_FAILURES - count} 次")
            conn.execute("DELETE FROM login_failures WHERE email=?", (email,))
            conn.commit()
            token = self._new_session(conn, email)
            return token, User(email, float(row["created_at"]))

    def login_code(self, email: str, code: str) -> tuple[str, User]:
        email = self._norm_email(email)
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT created_at FROM users WHERE email=?", (email,)
            ).fetchone()
            if row is None:
                raise AuthError("该邮箱尚未注册，请先注册")
            self._verify_code(conn, email, code, "login")
            token = self._new_session(conn, email)
            return token, User(email, float(row["created_at"]))

    def authenticate(self, token: str | None) -> User | None:
        if self.dev_bypass:
            return User("dev@localhost", 0.0)
        if not token:
            return None
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT email, expires_at FROM sessions WHERE token=?", (token,)
            ).fetchone()
            if row is None:
                return None
            if float(row["expires_at"]) < time.time():
                conn.execute("DELETE FROM sessions WHERE token=?", (token,))
                conn.commit()
                return None
            return User(str(row["email"]), 0.0)

    def logout(self, token: str | None) -> None:
        if not token:
            return
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token=?", (token,))
            conn.commit()

    def create_user_direct(self, email: str, password: str) -> bool:
        """Create an account without a code (tests / bootstrap only)."""
        email = self._norm_email(email)
        self._check_password(password)
        with self._lock, self._connect() as conn:
            if conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
                return False
            salt = secrets.token_bytes(16)
            conn.execute(
                "INSERT INTO users(email, password_hash, salt, created_at) VALUES(?,?,?,?)",
                (email, _hash_password(password, salt), salt.hex(), time.time()),
            )
            conn.commit()
            return True

    def cleanup(self) -> None:
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            conn.execute("DELETE FROM codes WHERE expires_at < ?", (now - 3600,))
            conn.execute("DELETE FROM login_failures WHERE updated_at < ?", (now - 86400,))
            conn.commit()

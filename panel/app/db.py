"""Base de datos SQLite: esquema, arranque y helpers."""
from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from . import security

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    must_change   INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tenants (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    must_change   INTEGER NOT NULL DEFAULT 1,
    net_index     INTEGER NOT NULL UNIQUE,
    max_devices   INTEGER NOT NULL DEFAULT 10,
    enabled       INTEGER NOT NULL DEFAULT 1,
    notes         TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id            INTEGER PRIMARY KEY,
    tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    ip            TEXT NOT NULL UNIQUE,
    private_key   TEXT NOT NULL,
    public_key    TEXT NOT NULL UNIQUE,
    preshared_key TEXT NOT NULL,
    full_tunnel   INTEGER NOT NULL DEFAULT 1,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_tenant ON devices(tenant_id);
"""


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def conn(self) -> Iterator[sqlite3.Connection]:
        # check_same_thread=False: FastAPI puede abrir la conexión (dependencia) y
        # usarla (endpoint) en hilos distintos del pool; nunca se comparte entre peticiones.
        c = sqlite3.connect(self.path, timeout=15, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON")
        try:
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()

    def init(self, admin_user: str, admin_password: str, keygen) -> None:
        """Crea el esquema, las claves del servidor y el admin inicial si faltan."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.conn() as c:
            c.execute("PRAGMA journal_mode = WAL")
            c.executescript(SCHEMA)
            if get_setting(c, "server_private_key") is None:
                private, public = keygen()
                set_setting(c, "server_private_key", private)
                set_setting(c, "server_public_key", public)
            if c.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 0:
                c.execute(
                    "INSERT INTO admins (username, password_hash, must_change, created_at) VALUES (?, ?, 1, ?)",
                    (admin_user, security.hash_password(admin_password), int(time.time())),
                )
        self.path.chmod(0o600)


def get_setting(c: sqlite3.Connection, key: str) -> str | None:
    row = c.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_setting(c: sqlite3.Connection, key: str, value: str) -> None:
    c.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def username_taken(c: sqlite3.Connection, username: str, exclude_tenant: int | None = None) -> bool:
    """Los usuarios son únicos entre admins y clientes (un solo formulario de login)."""
    if c.execute("SELECT 1 FROM admins WHERE username = ? COLLATE NOCASE", (username,)).fetchone():
        return True
    row = c.execute("SELECT id FROM tenants WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
    return bool(row) and row["id"] != exclude_tenant

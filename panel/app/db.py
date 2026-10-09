"""Base de datos SQLite: esquema, arranque y helpers."""
from __future__ import annotations

import re
import sqlite3
import time
import unicodedata
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
CREATE TABLE IF NOT EXISTS passkeys (
    id            INTEGER PRIMARY KEY,
    role          TEXT NOT NULL,
    user_id       INTEGER NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,
    public_key    BLOB NOT NULL,
    sign_count    INTEGER NOT NULL DEFAULT 0,
    rp_id         TEXT NOT NULL,
    name          TEXT NOT NULL,
    transports    TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(role, user_id);
CREATE TABLE IF NOT EXISTS services (
    id          INTEGER PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hostname    TEXT NOT NULL UNIQUE,
    target_ip   TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    scheme      TEXT NOT NULL DEFAULT 'http',
    auth_user   TEXT NOT NULL DEFAULT '',
    auth_hash   TEXT NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS forwards (
    id          INTEGER PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    proto       TEXT NOT NULL,
    public_port INTEGER NOT NULL,
    target_ip   TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS members (
    id            INTEGER PRIMARY KEY,
    tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    must_change   INTEGER NOT NULL DEFAULT 0,
    enabled       INTEGER NOT NULL DEFAULT 1,
    can_create    INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    last_login    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_members_tenant ON members(tenant_id);
CREATE TABLE IF NOT EXISTS invites (
    id         INTEGER PRIMARY KEY,
    tenant_id  INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    can_create INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    member_id  INTEGER
);
CREATE TABLE IF NOT EXISTS device_links (
    id         INTEGER PRIMARY KEY,
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    views      INTEGER NOT NULL DEFAULT 0,
    last_view  INTEGER
);
CREATE TABLE IF NOT EXISTS alert_channels (
    id         INTEGER PRIMARY KEY,
    role       TEXT NOT NULL,
    user_id    INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    target     TEXT NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    last_ok    INTEGER,
    last_error TEXT,
    UNIQUE (role, user_id, kind, target)
);
CREATE TABLE IF NOT EXISTS alert_prefs (
    role    TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    prefs   TEXT NOT NULL,
    PRIMARY KEY (role, user_id)
);
CREATE TABLE IF NOT EXISTS telegram_links (
    code       TEXT PRIMARY KEY,
    role       TEXT NOT NULL,
    user_id    INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS device_state (
    device_id      INTEGER PRIMARY KEY,
    rx             INTEGER NOT NULL DEFAULT 0,
    tx             INTEGER NOT NULL DEFAULT 0,
    online         INTEGER NOT NULL DEFAULT 0,
    changed_at     INTEGER NOT NULL DEFAULT 0,
    last_seen      INTEGER,
    endpoint       TEXT,
    alerted        INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS traffic_hourly (
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id INTEGER NOT NULL,
    hour      INTEGER NOT NULL,
    rx        INTEGER NOT NULL DEFAULT 0,
    tx        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, hour)
);
CREATE INDEX IF NOT EXISTS idx_traffic_hourly_tenant ON traffic_hourly(tenant_id, hour);
CREATE TABLE IF NOT EXISTS traffic_daily (
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id INTEGER NOT NULL,
    day       TEXT NOT NULL,
    rx        INTEGER NOT NULL DEFAULT 0,
    tx        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, day)
);
CREATE INDEX IF NOT EXISTS idx_traffic_daily_tenant ON traffic_daily(tenant_id, day);
CREATE TABLE IF NOT EXISTS conn_events (
    id        INTEGER PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id INTEGER NOT NULL,
    ts        INTEGER NOT NULL,
    kind      TEXT NOT NULL,
    endpoint  TEXT
);
CREATE INDEX IF NOT EXISTS idx_conn_events_tenant ON conn_events(tenant_id, ts);
CREATE INDEX IF NOT EXISTS idx_conn_events_device ON conn_events(device_id, ts);
CREATE TABLE IF NOT EXISTS dns_hourly (
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hour      INTEGER NOT NULL,
    queries   INTEGER NOT NULL DEFAULT 0,
    blocked   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, hour)
);
CREATE TABLE IF NOT EXISTS dns_daily (
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    day       TEXT NOT NULL,
    queries   INTEGER NOT NULL DEFAULT 0,
    blocked   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, day)
);
CREATE TABLE IF NOT EXISTS dns_top (
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    day       TEXT NOT NULL,
    domain    TEXT NOT NULL,
    count     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, day, domain)
);
CREATE TABLE IF NOT EXISTS dns_records (
    id         INTEGER PRIMARY KEY,
    tenant_id  INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    ip         TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (tenant_id, name)
);
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
            _migrate(c)
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


def _ensure_column(c: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    if column not in {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def _migrate(c: sqlite3.Connection) -> None:
    """Columnas añadidas en versiones posteriores (bases de datos existentes)."""
    _ensure_column(c, "tenants", "dns_filters", "TEXT NOT NULL DEFAULT '{}'")
    _ensure_column(c, "tenants", "dns_allow", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(c, "tenants", "dns_deny", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(c, "devices", "dns_filter", "INTEGER NOT NULL DEFAULT 1")
    _ensure_column(c, "tenants", "domain", "TEXT")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain) WHERE domain IS NOT NULL")
    _ensure_column(c, "tenants", "dns_upstream", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(c, "devices", "hostname", "TEXT")
    # Nombre DNS para los dispositivos que aún no lo tienen (bases anteriores).
    for row in c.execute("SELECT id, tenant_id, name FROM devices WHERE hostname IS NULL").fetchall():
        c.execute("UPDATE devices SET hostname = ? WHERE id = ?",
                  (unique_hostname(c, row["tenant_id"], make_hostname(row["name"])), row["id"]))
    _ensure_column(c, "devices", "kind", "TEXT NOT NULL DEFAULT 'device'")
    _ensure_column(c, "devices", "lan_networks", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(c, "tenants", "max_forwards", "INTEGER NOT NULL DEFAULT 5")
    _ensure_column(c, "devices", "member_id", "INTEGER REFERENCES members(id) ON DELETE SET NULL")
    if "monitor" not in {r["name"] for r in c.execute("PRAGMA table_info(devices)")}:
        # Avisar si se desconecta: activado por defecto en los routers existentes.
        _ensure_column(c, "devices", "monitor", "INTEGER NOT NULL DEFAULT 0")
        c.execute("UPDATE devices SET monitor = 1 WHERE kind = 'router'")
    if get_setting(c, "dns_suffixes") is None:
        set_setting(c, "dns_suffixes", "vpn")


# --------------------------------------------------------------------------- nombres DNS
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def make_hostname(name: str) -> str:
    """«Portátil de Ana» -> «portatil-de-ana» (etiqueta DNS válida)."""
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    label = re.sub(r"[^a-z0-9]+", "-", ascii_name.lower()).strip("-")[:63].strip("-")
    return label or "dispositivo"


def name_in_use(c: sqlite3.Connection, tenant_id: int, name: str, exclude_device: int | None = None,
                exclude_record: int | None = None) -> bool:
    """Los nombres son únicos dentro de la red de un cliente (dispositivos y registros)."""
    dev = c.execute("SELECT id FROM devices WHERE tenant_id = ? AND hostname = ?", (tenant_id, name)).fetchone()
    if dev and dev["id"] != exclude_device:
        return True
    rec = c.execute("SELECT id FROM dns_records WHERE tenant_id = ? AND name = ?", (tenant_id, name)).fetchone()
    return bool(rec) and rec["id"] != exclude_record


def unique_hostname(c: sqlite3.Connection, tenant_id: int, base: str, exclude_device: int | None = None) -> str:
    name, n = base, 2
    while name_in_use(c, tenant_id, name, exclude_device=exclude_device):
        suffix = f"-{n}"
        name = base[: 63 - len(suffix)] + suffix
        n += 1
    return name


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
    if c.execute("SELECT 1 FROM members WHERE username = ? COLLATE NOCASE", (username,)).fetchone():
        return True
    row = c.execute("SELECT id FROM tenants WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
    return bool(row) and row["id"] != exclude_tenant

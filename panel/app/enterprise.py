"""Cuentas Enterprise: un cliente que gestiona sus propias instalaciones, como un reseller sin cobros.

Una cuenta Enterprise (tabla `orgs`) entra en el panel con su usuario y ve sólo sus
instalaciones. Cada instalación es un cliente normal (red privada aislada, con sus
dispositivos, routers, servicios, puertos y usuarios) marcado con `org_id`.

Red: el administrador asigna a cada cuenta un bloque propio (p. ej. 10.20.0.0/16),
fuera de la red general de la VPN; cada instalación recibe la siguiente /24 libre
de ese bloque (10.20.0.0/24, 10.20.1.0/24…). El host enruta el bloque por wg0 y le
da salida a Internet con NAT (wgp/blocks.list); las instalaciones siguen aisladas
entre sí como cualquier cliente.

Sin facturación: la cuenta y sus instalaciones no pasan por Stripe. El administrador
fija los límites: número de instalaciones, dispositivos en total (que la cuenta
reparte entre sus instalaciones) y si pueden usar las salidas por país / IPs adicionales.

Sin `from __future__ import annotations`: FastAPI evalúa las dependencias de `deps`.
"""
import ipaddress
import sqlite3
import time
from typing import Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field, field_validator

from . import reserved, security, wg
from .db import username_taken

USERNAME_RE = r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,31}$"


def usage(c: sqlite3.Connection, org_id: int) -> dict:
    row = c.execute("""SELECT COUNT(*) AS installs, COALESCE(SUM(max_devices), 0) AS assigned
                       FROM tenants WHERE org_id = ?""", (org_id,)).fetchone()
    devices = c.execute("SELECT COUNT(*) FROM devices d JOIN tenants t ON t.id = d.tenant_id WHERE t.org_id = ?",
                        (org_id,)).fetchone()[0]
    return {"installs": row["installs"], "devices_assigned": row["assigned"], "devices": devices}


def summary(c: sqlite3.Connection, org_id: int) -> dict:
    o = c.execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone()
    if o is None:
        raise HTTPException(404, "Cuenta Enterprise no encontrada")
    u = usage(c, org_id)
    net = ipaddress.IPv4Network(o["network"])
    return {"id": o["id"], "name": o["name"], "username": o["username"], "network": o["network"],
            "max_installs": o["max_installs"], "max_devices": o["max_devices"], "allow_exits": bool(o["allow_exits"]),
            "enabled": bool(o["enabled"]), "notes": o["notes"], "created_at": o["created_at"],
            "must_change": bool(o["must_change"]), "installs": u["installs"], "devices": u["devices"],
            "devices_assigned": u["devices_assigned"],
            "network_capacity": 2 ** max(0, wg.ORG_PREFIX - net.prefixlen)}


class OrgIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    username: str = Field(pattern=USERNAME_RE)
    password: str = Field(min_length=8, max_length=256)
    network: Optional[str] = Field(default=None, max_length=18)   # vacío: se propone uno libre
    max_installs: int = Field(default=10, ge=1, le=4096)
    max_devices: int = Field(default=100, ge=1, le=100_000)
    allow_exits: bool = True
    notes: str = Field(default="", max_length=500)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        return " ".join(v.split())


class OrgPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=64)
    max_installs: Optional[int] = Field(default=None, ge=1, le=4096)
    max_devices: Optional[int] = Field(default=None, ge=1, le=100_000)
    allow_exits: Optional[bool] = None
    enabled: Optional[bool] = None
    notes: Optional[str] = Field(default=None, max_length=500)
    password: Optional[str] = Field(default=None, min_length=8, max_length=256)


def register(app, d) -> None:
    settings = d.settings

    def org_or_404(c: sqlite3.Connection, org_id: int) -> sqlite3.Row:
        row = c.execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Cuenta Enterprise no encontrada")
        return row

    def check_block(c: sqlite3.Connection, value: str, exclude: Optional[int] = None) -> ipaddress.IPv4Network:
        try:
            net = wg.check_org_block(c, settings, value, exclude)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        for other in d.wgm.host_networks():
            if net.overlaps(other):
                raise HTTPException(409, f"{net} se solapa con una red del propio servidor ({other}); elige otro rango")
        return net

    @app.get("/api/admin/orgs")
    def list_orgs(_: d.Admin, c: d.Conn):
        rows = c.execute("SELECT id FROM orgs ORDER BY name COLLATE NOCASE").fetchall()
        return {"orgs": [summary(c, r["id"]) for r in rows], "suggested_network": wg.suggest_org_block(c, settings),
                "vpn_network": str(settings.wg_subnet)}

    @app.post("/api/admin/orgs", status_code=201)
    def create_org(body: OrgIn, _: d.Admin, c: d.Conn):
        if username_taken(c, body.username):
            raise HTTPException(409, "Ese nombre de usuario ya existe")
        reserved.check_username(c, body.username)
        raw = (body.network or "").strip() or wg.suggest_org_block(c, settings)
        if not raw:
            raise HTTPException(409, "No queda ningún bloque 10.x.0.0/16 libre: indica uno")
        net = check_block(c, raw)
        cur = c.execute(
            """INSERT INTO orgs (name, username, password_hash, must_change, network, max_installs, max_devices,
                                 allow_exits, notes, created_at)
               VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?)""",
            (body.name, body.username, security.hash_password(body.password), str(net), body.max_installs,
             body.max_devices, int(body.allow_exits), body.notes.strip(), int(time.time())))
        c.commit()
        d.apply_wg()
        return summary(c, cur.lastrowid)

    @app.get("/api/admin/orgs/{org_id}")
    def get_org(org_id: int, _: d.Admin, c: d.Conn):
        org_or_404(c, org_id)
        return summary(c, org_id)

    @app.patch("/api/admin/orgs/{org_id}")
    def patch_org(org_id: int, body: OrgPatch, _: d.Admin, c: d.Conn):
        o = org_or_404(c, org_id)
        u = usage(c, org_id)
        if body.max_installs is not None and body.max_installs < u["installs"]:
            raise HTTPException(409, f"La cuenta ya tiene {u['installs']} instalaciones")
        if body.max_devices is not None and body.max_devices < u["devices_assigned"]:
            raise HTTPException(409, f"Ya ha repartido {u['devices_assigned']} dispositivos entre sus instalaciones")
        if body.name is not None:
            c.execute("UPDATE orgs SET name = ? WHERE id = ?", (" ".join(body.name.split()), org_id))
        for field in ("max_installs", "max_devices", "notes"):
            value = getattr(body, field)
            if value is not None:
                c.execute(f"UPDATE orgs SET {field} = ? WHERE id = ?", (value, org_id))
        if body.allow_exits is not None:
            c.execute("UPDATE orgs SET allow_exits = ? WHERE id = ?", (int(body.allow_exits), org_id))
            c.execute("UPDATE tenants SET allow_exits = ? WHERE org_id = ?", (int(body.allow_exits), org_id))
        if body.password is not None:
            c.execute("UPDATE orgs SET password_hash = ?, must_change = 1 WHERE id = ?",
                      (security.hash_password(body.password), org_id))
        if body.enabled is not None and bool(o["enabled"]) != body.enabled:
            # Deshabilitar la cuenta corta también sus instalaciones (y al revés).
            c.execute("UPDATE orgs SET enabled = ? WHERE id = ?", (int(body.enabled), org_id))
            if body.enabled:
                c.execute("UPDATE tenants SET enabled = 1, suspended_reason = '' WHERE org_id = ? AND suspended_reason = 'org'",
                          (org_id,))
            else:
                c.execute("UPDATE tenants SET enabled = 0, suspended_reason = 'org' WHERE org_id = ? AND enabled = 1",
                          (org_id,))
        c.commit()
        d.apply_wg()
        return summary(c, org_id)

    @app.delete("/api/admin/orgs/{org_id}")
    def delete_org(org_id: int, _: d.Admin, c: d.Conn):
        org_or_404(c, org_id)
        for t in c.execute("SELECT * FROM tenants WHERE org_id = ?", (org_id,)).fetchall():
            d.remove_tenant(c, t)
        for table in ("passkeys", "alert_channels", "alert_prefs", "account_security"):
            c.execute(f"DELETE FROM {table} WHERE role = 'org' AND user_id = ?", (org_id,))
        c.execute("DELETE FROM orgs WHERE id = ?", (org_id,))
        c.commit()
        d.apply_wg()
        return {"ok": True}

    @app.get("/api/org")
    def my_org(p: d.Manager, c: d.Conn):
        if not p.is_org:
            raise HTTPException(403, "Sólo cuentas Enterprise")
        return summary(c, p.id)

"""Reenvío de puertos TCP/UDP: IP_pública:puerto -> equipo de la red de un cliente.

El panel sólo guarda los reenvíos y escribe wgp/forwards.list; el host
(wgp-firewall) valida cada línea, rechaza los puertos del propio servidor y
crea las reglas DNAT/SNAT. La conexión llega al equipo con la IP del servidor
como origen, así la respuesta vuelve siempre por el túnel.

Sin `from __future__ import annotations`: FastAPI necesita evaluar las
anotaciones (dependencias) que llegan en `deps`.
"""
import asyncio
import os
import random
import sqlite3
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import cfdns

BASE_RESERVED = {53, 80, 443, 2019}
TENANT_MIN_PORT = 1024
SUGGEST_RANGE = (20000, 29999)


class ForwardIn(BaseModel):
    proto: str = Field(default="tcp", pattern="^(tcp|udp|both)$")
    public_port: int = Field(ge=1, le=65535)
    target_ip: str = Field(min_length=7, max_length=15)
    target_port: int = Field(ge=1, le=65535)
    description: str = Field(default="", max_length=60)
    tenant_id: int | None = None  # sólo admin


class ForwardUpdate(BaseModel):
    enabled: bool | None = None
    target_ip: str | None = Field(default=None, min_length=7, max_length=15)
    target_port: int | None = Field(default=None, ge=1, le=65535)
    description: str | None = Field(default=None, max_length=60)


def reserved_ports(settings) -> set[int]:
    """Puertos del propio servidor (los calcula wg-manager: SSH, panel, WireGuard…)."""
    out = set(BASE_RESERVED) | {settings.wg_port}
    for raw in (os.environ.get("RESERVED_PORTS", "") + " " + os.environ.get("PANEL_PORT", "5000")).split():
        if raw.isdigit():
            out.add(int(raw))
    return out


def protos(value: str) -> set[str]:
    return {"tcp", "udp"} if value == "both" else {value}


def conflict(c: sqlite3.Connection, proto: str, port: int, exclude: int | None = None) -> bool:
    for r in c.execute("SELECT id, proto FROM forwards WHERE public_port = ?", (port,)):
        if r["id"] != exclude and protos(r["proto"]) & protos(proto):
            return True
    return False


def register(app: FastAPI, d) -> None:
    settings = d.settings

    def forward_json(c: sqlite3.Connection, r: sqlite3.Row) -> dict:
        dev = c.execute("SELECT name FROM devices WHERE tenant_id = ? AND ip = ?", (r["tenant_id"], r["target_ip"])).fetchone()
        return {
            "id": r["id"], "tenant_id": r["tenant_id"], "proto": r["proto"], "public_port": r["public_port"],
            "target_ip": r["target_ip"], "target_port": r["target_port"], "description": r["description"],
            "enabled": bool(r["enabled"]), "created_at": r["created_at"], "target_name": dev["name"] if dev else None,
        }

    def forward_for(c: sqlite3.Connection, p, forward_id: int) -> sqlite3.Row:
        row = c.execute("SELECT * FROM forwards WHERE id = ?", (forward_id,)).fetchone()
        if not row or (not p.is_admin and row["tenant_id"] != p.id):
            raise HTTPException(404, "Reenvío no encontrado")
        return row

    def suggest(c: sqlite3.Connection) -> int | None:
        used = {r[0] for r in c.execute("SELECT public_port FROM forwards")} | reserved_ports(settings)
        free = [p for p in range(SUGGEST_RANGE[0], SUGGEST_RANGE[1] + 1) if p not in used]
        return random.choice(free) if free else None

    @app.get("/api/forwards")
    def list_forwards(p: d.User, c: d.Conn, tenant_id: int | None = None):
        tid = d.scope_tenant(p, tenant_id)
        t = d.tenant_or_404(c, tid)
        rows = c.execute("SELECT * FROM forwards WHERE tenant_id = ? ORDER BY public_port", (tid,)).fetchall()
        return {
            "max": t["max_forwards"], "public_host": (d.tenant_host(c, t) if not cfdns.tenant_proxied(c, t) else None) or d.endpoint_host(c), "server_ips": sorted(d.doms.expected_ips()),
            "min_port": 1 if p.is_admin else TENANT_MIN_PORT, "suggested_port": suggest(c),
            "networks": d.tenant_networks(c, tid), "forwards": [forward_json(c, r) for r in rows],
        }

    @app.post("/api/forwards", status_code=201)
    def create_forward(body: ForwardIn, p: d.User, c: d.Conn):
        tid = body.tenant_id if p.is_admin else p.id
        if tid is None:
            raise HTTPException(400, "tenant_id es obligatorio")
        t = d.tenant_or_404(c, tid)
        count = c.execute("SELECT COUNT(*) FROM forwards WHERE tenant_id = ?", (tid,)).fetchone()[0]
        if count >= t["max_forwards"]:
            raise HTTPException(409, "Sin puertos disponibles: pide a tu proveedor que amplíe el límite"
                                if t["max_forwards"] == 0 or not p.is_admin else
                                f"Límite de puertos de este cliente alcanzado ({t['max_forwards']})")
        port = body.public_port
        if port in reserved_ports(settings):
            raise HTTPException(409, f"El puerto {port} lo usa el propio servidor; elige otro")
        if not p.is_admin and port < TENANT_MIN_PORT:
            raise HTTPException(422, f"Elige un puerto público entre {TENANT_MIN_PORT} y 65535")
        if conflict(c, body.proto, port):
            raise HTTPException(409, f"El puerto {port} ya está en uso; elige otro")
        target = d.clean_target(c, tid, body.target_ip)
        cur = c.execute(
            """INSERT INTO forwards (tenant_id, proto, public_port, target_ip, target_port, description, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (tid, body.proto, port, target, body.target_port, body.description.strip(), int(time.time())),
        )
        c.commit()
        d.apply_wg()
        return forward_json(c, c.execute("SELECT * FROM forwards WHERE id = ?", (cur.lastrowid,)).fetchone())

    @app.patch("/api/forwards/{forward_id}")
    def update_forward(forward_id: int, body: ForwardUpdate, p: d.User, c: d.Conn):
        r = forward_for(c, p, forward_id)
        if body.target_ip is not None:
            c.execute("UPDATE forwards SET target_ip = ? WHERE id = ?", (d.clean_target(c, r["tenant_id"], body.target_ip), forward_id))
        if body.target_port is not None:
            c.execute("UPDATE forwards SET target_port = ? WHERE id = ?", (body.target_port, forward_id))
        if body.description is not None:
            c.execute("UPDATE forwards SET description = ? WHERE id = ?", (body.description.strip(), forward_id))
        if body.enabled is not None:
            c.execute("UPDATE forwards SET enabled = ? WHERE id = ?", (int(body.enabled), forward_id))
        c.commit()
        d.apply_wg()
        return forward_json(c, c.execute("SELECT * FROM forwards WHERE id = ?", (forward_id,)).fetchone())

    @app.delete("/api/forwards/{forward_id}")
    def delete_forward(forward_id: int, p: d.User, c: d.Conn):
        forward_for(c, p, forward_id)
        c.execute("DELETE FROM forwards WHERE id = ?", (forward_id,))
        c.commit()
        d.apply_wg()
        return {"ok": True}

    @app.get("/api/forwards/{forward_id}/status")
    async def forward_status(forward_id: int, p: d.User, c: d.Conn):
        r = forward_for(c, p, forward_id)
        if r["proto"] == "udp":
            return {"target": {"ok": None, "error": "UDP no se puede comprobar: prueba desde fuera con tu aplicación"}}
        return {"target": await asyncio.to_thread(d.probe, r["target_ip"], r["target_port"])}

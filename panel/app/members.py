"""Usuarios dentro de un cliente, invitaciones y enlaces para instalar un dispositivo.

* El responsable del cliente (o el admin) crea usuarios o les envía una
  invitación (enlace de un solo uso, 7 días). Cada usuario sólo ve y gestiona
  sus propios dispositivos, su actividad y sus avisos.
* Enlace de instalación: una URL temporal (1 h, 24 h o 7 días) con el QR y el
  .conf de un dispositivo, para pasárselo a quien lo va a usar sin darle una
  cuenta. Los tokens se guardan sólo como hash.

Sin `from __future__ import annotations`: FastAPI evalúa las dependencias de `deps`.
"""
import hashlib
import io
import re
import secrets
import sqlite3
import time

import segno
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

from . import security
from .db import username_taken

USERNAME_RE = r"^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$"
INVITE_TTL = 7 * 86400
LINK_HOURS = (1, 24, 168)
MAX_MEMBERS = 200


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def clean_name(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    if not value:
        raise HTTPException(422, "El nombre no puede estar vacío")
    return value


class MemberIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    username: str = Field(pattern=USERNAME_RE)
    password: str = Field(min_length=8, max_length=256)
    can_create: bool = True
    tenant_id: int | None = None  # sólo admin


class InviteIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    can_create: bool = True
    tenant_id: int | None = None


class MemberUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=64)
    enabled: bool | None = None
    can_create: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=256)


class AcceptIn(BaseModel):
    username: str = Field(pattern=USERNAME_RE)
    password: str = Field(min_length=8, max_length=256)


class LinkIn(BaseModel):
    hours: int = 24


def base_url(request: Request) -> str:
    host = request.headers.get("host", "localhost")
    return f"{request.url.scheme}://{host}"


def register(app: FastAPI, d) -> None:

    def member_json(c: sqlite3.Connection, m: sqlite3.Row) -> dict:
        devices = c.execute("SELECT COUNT(*) FROM devices WHERE member_id = ?", (m["id"],)).fetchone()[0]
        return {"id": m["id"], "tenant_id": m["tenant_id"], "name": m["name"], "username": m["username"],
                "enabled": bool(m["enabled"]), "can_create": bool(m["can_create"]), "must_change": bool(m["must_change"]),
                "created_at": m["created_at"], "last_login": m["last_login"], "devices": devices}

    def member_for(c: sqlite3.Connection, p, member_id: int) -> sqlite3.Row:
        row = c.execute("SELECT * FROM members WHERE id = ?", (member_id,)).fetchone()
        if not row or (not p.is_admin and row["tenant_id"] != p.id):
            raise HTTPException(404, "Usuario no encontrado")
        return row

    def target_tenant(p, c: sqlite3.Connection, tenant_id: int | None) -> int:
        tid = d.scope_tenant(p, tenant_id)
        d.tenant_or_404(c, tid)
        limit = min(MAX_MEMBERS, d.tenant_or_404(c, tid)["max_members"])
        if c.execute("SELECT COUNT(*) FROM members WHERE tenant_id = ?", (tid,)).fetchone()[0] >= limit:
            raise HTTPException(409, f"Tu plan incluye {limit} usuarios: amplíalo para invitar a más" if limit
                                else "Tu plan no incluye usuarios adicionales")
        return tid

    def listing(c: sqlite3.Connection, tid: int) -> dict:
        members = c.execute("SELECT * FROM members WHERE tenant_id = ? ORDER BY name COLLATE NOCASE", (tid,)).fetchall()
        invites = c.execute("""SELECT id, name, can_create, created_at, expires_at FROM invites
                               WHERE tenant_id = ? AND used_at IS NULL AND expires_at > ? ORDER BY created_at DESC""",
                            (tid, int(time.time()))).fetchall()
        return {"members": [member_json(c, m) for m in members], "invites": [dict(i) for i in invites]}

    # ---------------------------------------------------------------- gestión (responsable / admin)
    @app.get("/api/members")
    def list_members(p: d.User, c: d.Conn, tenant_id: int | None = None):
        tid = d.scope_tenant(p, tenant_id)
        d.tenant_or_404(c, tid)
        return listing(c, tid)

    @app.post("/api/members", status_code=201)
    def create_member(body: MemberIn, p: d.User, c: d.Conn):
        tid = target_tenant(p, c, body.tenant_id)
        if username_taken(c, body.username):
            raise HTTPException(409, "Ese nombre de usuario ya existe")
        cur = c.execute(
            """INSERT INTO members (tenant_id, username, name, password_hash, must_change, can_create, created_at)
               VALUES (?, ?, ?, ?, 1, ?, ?)""",
            (tid, body.username, clean_name(body.name), security.hash_password(body.password), int(body.can_create),
             int(time.time())))
        return member_json(c, c.execute("SELECT * FROM members WHERE id = ?", (cur.lastrowid,)).fetchone())

    @app.patch("/api/members/{member_id}")
    def update_member(member_id: int, body: MemberUpdate, p: d.User, c: d.Conn):
        m = member_for(c, p, member_id)
        if body.name is not None:
            c.execute("UPDATE members SET name = ? WHERE id = ?", (clean_name(body.name), member_id))
        if body.enabled is not None:
            c.execute("UPDATE members SET enabled = ? WHERE id = ?", (int(body.enabled), member_id))
        if body.can_create is not None:
            c.execute("UPDATE members SET can_create = ? WHERE id = ?", (int(body.can_create), member_id))
        if body.password is not None:
            c.execute("UPDATE members SET password_hash = ?, must_change = 1 WHERE id = ?",
                      (security.hash_password(body.password), member_id))
        return member_json(c, c.execute("SELECT * FROM members WHERE id = ?", (m["id"],)).fetchone())

    @app.delete("/api/members/{member_id}")
    def delete_member(member_id: int, p: d.User, c: d.Conn):
        """Sus dispositivos se quedan en el cliente, sin asignar (el responsable decide)."""
        member_for(c, p, member_id)
        c.execute("UPDATE devices SET member_id = NULL WHERE member_id = ?", (member_id,))
        for table in ("passkeys", "alert_channels", "alert_prefs"):
            c.execute(f"DELETE FROM {table} WHERE role = 'member' AND user_id = ?", (member_id,))
        c.execute("DELETE FROM members WHERE id = ?", (member_id,))
        return {"ok": True}

    @app.post("/api/members/invite", status_code=201)
    def invite(body: InviteIn, request: Request, p: d.User, c: d.Conn):
        tid = target_tenant(p, c, body.tenant_id)
        token = secrets.token_urlsafe(32)
        expires = int(time.time()) + INVITE_TTL
        c.execute("""INSERT INTO invites (tenant_id, token_hash, name, can_create, created_at, expires_at)
                     VALUES (?, ?, ?, ?, ?, ?)""",
                  (tid, token_hash(token), clean_name(body.name), int(body.can_create), int(time.time()), expires))
        return {"url": f"{base_url(request)}/#/invite/{token}", "expires_at": expires}

    @app.delete("/api/invites/{invite_id}")
    def delete_invite(invite_id: int, p: d.User, c: d.Conn):
        row = c.execute("SELECT tenant_id FROM invites WHERE id = ?", (invite_id,)).fetchone()
        if not row or (not p.is_admin and row["tenant_id"] != p.id):
            raise HTTPException(404, "Invitación no encontrada")
        c.execute("DELETE FROM invites WHERE id = ?", (invite_id,))
        return {"ok": True}

    # ---------------------------------------------------------------- invitación (público)
    def invite_or_404(c: sqlite3.Connection, token: str) -> sqlite3.Row:
        row = c.execute("""SELECT i.*, t.name AS tenant_name, t.enabled AS tenant_enabled FROM invites i
                           JOIN tenants t ON t.id = i.tenant_id WHERE i.token_hash = ?""", (token_hash(token),)).fetchone()
        if not row or row["used_at"] or row["expires_at"] < time.time() or not row["tenant_enabled"]:
            raise HTTPException(404, "La invitación no es válida o ha caducado. Pide una nueva.")
        return row

    @app.get("/api/invite/{token}")
    def invite_info(token: str, c: d.Conn):
        row = invite_or_404(c, token)
        return {"tenant": row["tenant_name"], "name": row["name"], "expires_at": row["expires_at"]}

    @app.post("/api/invite/{token}")
    def accept_invite(token: str, body: AcceptIn, request: Request, response: Response, c: d.Conn):
        key = request.client.host if request.client else "unknown"
        if d.limiter.blocked(key):
            raise HTTPException(429, "Demasiados intentos. Espere unos minutos.")
        try:
            row = invite_or_404(c, token)
        except HTTPException:
            d.limiter.hit(key)
            raise
        if username_taken(c, body.username):
            raise HTTPException(409, "Ese nombre de usuario ya existe; elige otro")
        password_hash = security.hash_password(body.password)
        cur = c.execute(
            """INSERT INTO members (tenant_id, username, name, password_hash, must_change, can_create, created_at, last_login)
               VALUES (?, ?, ?, ?, 0, ?, ?, ?)""",
            (row["tenant_id"], body.username, row["name"], password_hash, row["can_create"], int(time.time()), int(time.time())))
        c.execute("UPDATE invites SET used_at = ?, member_id = ? WHERE id = ?", (int(time.time()), cur.lastrowid, row["id"]))
        d.set_session(request, response, "member", cur.lastrowid, password_hash)
        return {"role": "member", "must_change": False}

    # ---------------------------------------------------------------- enlace de instalación
    def link_state(c: sqlite3.Connection, device_id: int) -> dict:
        row = c.execute("SELECT * FROM device_links WHERE device_id = ? AND expires_at > ?",
                        (device_id, int(time.time()))).fetchone()
        return {"active": bool(row), "expires_at": row["expires_at"] if row else None,
                "views": row["views"] if row else 0, "last_view": row["last_view"] if row else None}

    @app.get("/api/devices/{device_id}/link")
    def get_link(device_id: int, p: d.Anyone, c: d.Conn):
        d.device_for(c, p, device_id)
        return link_state(c, device_id)

    @app.post("/api/devices/{device_id}/link", status_code=201)
    def create_link(device_id: int, body: LinkIn, request: Request, p: d.Anyone, c: d.Conn):
        dev = d.device_for(c, p, device_id)
        if body.hours not in LINK_HOURS:
            raise HTTPException(422, "Duración no válida (1, 24 o 168 horas)")
        if dev["kind"] == "router":
            raise HTTPException(422, "Los routers se configuran con su script, no con enlace")
        token = secrets.token_urlsafe(32)
        c.execute("DELETE FROM device_links WHERE device_id = ?", (device_id,))  # un enlace activo por dispositivo
        c.execute("INSERT INTO device_links (device_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)",
                  (device_id, token_hash(token), int(time.time()), int(time.time()) + body.hours * 3600))
        return {**link_state(c, device_id), "url": f"{base_url(request)}/#/get/{token}"}

    @app.delete("/api/devices/{device_id}/link")
    def delete_link(device_id: int, p: d.Anyone, c: d.Conn):
        d.device_for(c, p, device_id)
        c.execute("DELETE FROM device_links WHERE device_id = ?", (device_id,))
        return link_state(c, device_id)

    def shared_device(c: sqlite3.Connection, token: str, request: Request) -> sqlite3.Row:
        key = request.client.host if request.client else "unknown"
        if d.limiter.blocked(key):
            raise HTTPException(429, "Demasiados intentos. Espere unos minutos.")
        row = c.execute("""SELECT l.id AS link_id, l.expires_at, dv.*, t.enabled AS tenant_enabled FROM device_links l
                           JOIN devices dv ON dv.id = l.device_id JOIN tenants t ON t.id = dv.tenant_id
                           WHERE l.token_hash = ?""", (token_hash(token),)).fetchone()
        if not row or row["expires_at"] < time.time() or not row["enabled"] or not row["tenant_enabled"]:
            d.limiter.hit(key)
            raise HTTPException(404, "El enlace no es válido o ha caducado. Pide uno nuevo.")
        return row

    @app.get("/api/get/{token}")
    def shared_config(token: str, request: Request, c: d.Conn):
        row = shared_device(c, token, request)
        c.execute("UPDATE device_links SET views = views + 1, last_view = ? WHERE id = ?", (int(time.time()), row["link_id"]))
        conf, slug = d.render_config(c, row)
        tenant = d.tenant_or_404(c, row["tenant_id"])
        return {"device": row["name"], "tenant": tenant["name"], "conf": conf, "filename": f"{slug}.conf",
                "expires_at": row["expires_at"], "full_tunnel": bool(row["full_tunnel"])}

    @app.get("/api/get/{token}/qr.svg")
    def shared_qr(token: str, request: Request, c: d.Conn):
        row = shared_device(c, token, request)
        conf, _ = d.render_config(c, row)
        buf = io.BytesIO()
        segno.make(conf, error="m").save(buf, kind="svg", scale=5, border=2, dark="#000", light="#fff")
        return Response(buf.getvalue(), media_type="image/svg+xml", headers={"Cache-Control": "no-store"})

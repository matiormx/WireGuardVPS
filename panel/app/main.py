"""API HTTP y servidor de la SPA del panel WireGuard Multi-Tenant."""

import hashlib
import io
import json
import logging
import re
import sqlite3
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import segno
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from . import dnsfilter, security, wg
from .config import Settings, load_settings
from .db import Database, get_setting, username_taken

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


def _static_version() -> str:
    """Hash de los estáticos: versión del service worker (cambia en cada despliegue)."""
    digest = hashlib.sha256()
    for path in sorted(STATIC_DIR.rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(STATIC_DIR).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()[:12]
log = logging.getLogger("wgp")

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
USERNAME_RE = r"^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$"


def _clean_name(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("No puede estar vacío")
    if _CONTROL.search(value):
        raise ValueError("Contiene caracteres no permitidos")
    return value


# ----------------------------------------------------------------------------- modelos
class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class PasswordIn(BaseModel):
    current: str = Field(min_length=1, max_length=256)
    new: str = Field(min_length=8, max_length=256)


class TenantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    username: str = Field(pattern=USERNAME_RE)
    password: str = Field(min_length=8, max_length=256)
    max_devices: int = Field(default=10, ge=1, le=16384)
    notes: str = Field(default="", max_length=500)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        return _clean_name(v)


class TenantUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=64)
    enabled: bool | None = None
    max_devices: int | None = Field(default=None, ge=1, le=16384)
    notes: str | None = Field(default=None, max_length=500)
    password: str | None = Field(default=None, min_length=8, max_length=256)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str | None) -> str | None:
        return None if v is None else _clean_name(v)


class DeviceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=48)
    full_tunnel: bool = True
    tenant_id: int | None = None  # sólo admin

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        return _clean_name(v)


class DeviceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=48)
    enabled: bool | None = None
    full_tunnel: bool | None = None
    dns_filter: bool | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str | None) -> str | None:
        return None if v is None else _clean_name(v)


class FiltersIn(BaseModel):
    ads: bool = False
    security: bool = False
    adult: bool = False
    gambling: bool = False
    safesearch: bool = False
    allowlist: list[str] = Field(default_factory=list, max_length=500)
    denylist: list[str] = Field(default_factory=list, max_length=500)

    @field_validator("allowlist", "denylist")
    @classmethod
    def _domains(cls, values: list[str]) -> list[str]:
        out: list[str] = []
        for v in values:
            d = dnsfilter.normalize_domain(v)
            if d is None:
                raise ValueError(f"Dominio no válido: {v!r}")
            if d not in out:
                out.append(d)
        return out


@dataclass
class Principal:
    role: str
    id: int
    username: str
    name: str
    must_change: bool

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


# --------------------------------------------------------------------------------- app
def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    database = Database(settings.data_dir / "panel.db")
    database.init(settings.admin_user, settings.admin_password, wg.generate_keypair)
    wgm = wg.WireGuardManager(settings, database)
    sessions = security.SessionManager(settings.session_secret, settings.session_hours * 3600)
    limiter = security.RateLimiter(limit=10, window=300)
    dns = dnsfilter.DnsFilter(settings, database)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            wgm.apply()
        except Exception:  # noqa: BLE001 - el panel debe arrancar aunque falle la aplicación
            log.exception("No se pudo aplicar la configuración WireGuard al arrancar")
        if settings.dns_enabled:
            await dns.start()
        yield
        await dns.stop()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings, app.state.db, app.state.wg, app.state.dns = settings, database, wgm, dns

    # ------------------------------------------------------------------ middleware
    @app.middleware("http")
    async def guard(request: Request, call_next):
        # CSRF: toda petición mutante a la API debe llevar la cabecera X-WGP.
        # Un formulario o <img> de otro sitio no puede añadir cabeceras propias
        # sin un preflight CORS, que este servidor nunca autoriza.
        if request.url.path.startswith("/api/") and request.method not in {"GET", "HEAD", "OPTIONS"}:
            if request.headers.get("x-wgp") != "1":
                return JSONResponse({"detail": "Falta la cabecera X-WGP"}, status_code=403)
        response = await call_next(request)
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; "
            "manifest-src 'self'; worker-src 'self'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    # ------------------------------------------------------------------ dependencias
    def db_conn():
        with database.conn() as c:
            yield c

    Conn = Annotated[sqlite3.Connection, Depends(db_conn)]

    def principal(request: Request, c: Conn) -> Principal:
        data = sessions.load(request.cookies.get(sessions.COOKIE))
        if not data:
            raise HTTPException(401, "Sesión no válida")
        if data["role"] == "admin":
            row = c.execute("SELECT * FROM admins WHERE id = ?", (data["uid"],)).fetchone()
            name = row["username"] if row else ""
        else:
            row = c.execute("SELECT * FROM tenants WHERE id = ? AND enabled = 1", (data["uid"],)).fetchone()
            name = row["name"] if row else ""
        if not row or security.password_version(row["password_hash"]) != data.get("pwv"):
            raise HTTPException(401, "Sesión caducada")
        return Principal(data["role"], row["id"], row["username"], name, bool(row["must_change"]))

    AnyUser = Annotated[Principal, Depends(principal)]

    def ready(p: AnyUser) -> Principal:
        if p.must_change:
            raise HTTPException(403, "password_change_required")
        return p

    User = Annotated[Principal, Depends(ready)]

    def admin(p: User) -> Principal:
        if not p.is_admin:
            raise HTTPException(403, "Sólo administradores")
        return p

    Admin = Annotated[Principal, Depends(admin)]

    def set_session(response: Response, role: str, uid: int, password_hash: str) -> None:
        response.set_cookie(
            sessions.COOKIE, sessions.dump(role, uid, security.password_version(password_hash)),
            max_age=sessions.max_age, httponly=True, samesite="strict", secure=settings.cookie_secure, path="/",
        )

    # ------------------------------------------------------------------ helpers
    def tenant_or_404(c: sqlite3.Connection, tenant_id: int) -> sqlite3.Row:
        row = c.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Cliente no encontrado")
        return row

    def device_for(c: sqlite3.Connection, p: Principal, device_id: int) -> sqlite3.Row:
        row = c.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not row or (not p.is_admin and row["tenant_id"] != p.id):
            raise HTTPException(404, "Dispositivo no encontrado")
        return row

    def device_json(d: sqlite3.Row, tenant: sqlite3.Row, stats: dict) -> dict:
        st = stats.get(d["public_key"], {})
        return {
            "id": d["id"], "tenant_id": d["tenant_id"], "tenant_name": tenant["name"],
            "name": d["name"], "ip": d["ip"], "public_key": d["public_key"],
            "full_tunnel": bool(d["full_tunnel"]), "enabled": bool(d["enabled"]),
            "dns_filter": bool(d["dns_filter"]),
            "created_at": d["created_at"],
            "online": bool(st.get("online")) and bool(d["enabled"]) and bool(tenant["enabled"]),
            "last_handshake": st.get("last_handshake"), "endpoint": st.get("endpoint"),
            "rx": st.get("rx", 0), "tx": st.get("tx", 0),
        }

    def tenant_json(c: sqlite3.Connection, t: sqlite3.Row, stats: dict) -> dict:
        devices = c.execute("SELECT * FROM devices WHERE tenant_id = ?", (t["id"],)).fetchall()
        dj = [device_json(d, t, stats) for d in devices]
        return {
            "id": t["id"], "name": t["name"], "username": t["username"],
            "network": str(wg.tenant_network(settings, t["net_index"])),
            "max_devices": t["max_devices"], "enabled": bool(t["enabled"]), "notes": t["notes"],
            "created_at": t["created_at"], "must_change": bool(t["must_change"]),
            "filters": dnsfilter.parse_filters(t["dns_filters"]),
            "device_count": len(dj), "online_count": sum(d["online"] for d in dj),
            "rx": sum(d["rx"] for d in dj), "tx": sum(d["tx"] for d in dj),
        }

    def apply_wg() -> None:
        dns.reload_policies()
        try:
            wgm.apply()
        except OSError as exc:
            log.exception("Error escribiendo la configuración WireGuard")
            raise HTTPException(500, f"No se pudo aplicar la configuración: {exc}") from exc

    # ------------------------------------------------------------------ auth
    @app.post("/api/auth/login")
    def login(body: LoginIn, request: Request, response: Response, c: Conn):
        key = request.client.host if request.client else "unknown"
        if limiter.blocked(key):
            raise HTTPException(429, "Demasiados intentos. Espere unos minutos.")
        role, row = "admin", c.execute(
            "SELECT * FROM admins WHERE username = ? COLLATE NOCASE", (body.username,)
        ).fetchone()
        if not row:
            role, row = "tenant", c.execute(
                "SELECT * FROM tenants WHERE username = ? COLLATE NOCASE", (body.username,)
            ).fetchone()
        if not row or not security.verify_password(body.password, row["password_hash"]):
            limiter.hit(key)
            raise HTTPException(401, "Usuario o contraseña incorrectos")
        if role == "tenant" and not row["enabled"]:
            raise HTTPException(403, "Cuenta deshabilitada. Contacte con su proveedor.")
        limiter.reset(key)
        set_session(response, role, row["id"], row["password_hash"])
        return {"role": role, "must_change": bool(row["must_change"])}

    @app.post("/api/auth/logout")
    def logout(response: Response):
        response.delete_cookie(sessions.COOKIE, path="/")
        return {"ok": True}

    @app.get("/api/me")
    def me(p: AnyUser, c: Conn):
        data = {"role": p.role, "id": p.id, "username": p.username, "name": p.name, "must_change": p.must_change}
        if not p.is_admin:
            t = tenant_or_404(c, p.id)
            data.update(network=str(wg.tenant_network(settings, t["net_index"])), max_devices=t["max_devices"])
        return data

    @app.post("/api/me/password")
    def change_password(body: PasswordIn, p: AnyUser, response: Response, c: Conn):
        table = "admins" if p.is_admin else "tenants"
        row = c.execute(f"SELECT password_hash FROM {table} WHERE id = ?", (p.id,)).fetchone()
        if not security.verify_password(body.current, row["password_hash"]):
            raise HTTPException(400, "La contraseña actual no es correcta")
        if body.new == body.current:
            raise HTTPException(400, "La nueva contraseña debe ser distinta")
        new_hash = security.hash_password(body.new)
        c.execute(f"UPDATE {table} SET password_hash = ?, must_change = 0 WHERE id = ?", (new_hash, p.id))
        set_session(response, p.role, p.id, new_hash)  # el resto de sesiones quedan invalidadas
        return {"ok": True}

    # ------------------------------------------------------------------ admin
    @app.get("/api/admin/overview")
    def overview(_: Admin, c: Conn):
        stats = wgm.stats()
        tenants = c.execute("SELECT * FROM tenants").fetchall()
        tj = [tenant_json(c, t, stats) for t in tenants]
        return {
            "tenants": len(tj), "tenants_enabled": sum(t["enabled"] for t in tj),
            "tenant_capacity": settings.tenant_capacity,
            "devices": sum(t["device_count"] for t in tj), "online": sum(t["online_count"] for t in tj),
            "rx": sum(t["rx"] for t in tj), "tx": sum(t["tx"] for t in tj),
            "top": sorted(tj, key=lambda t: t["rx"] + t["tx"], reverse=True)[:5],
            "dns": {
                "enabled": settings.dns_enabled, "running": dns.running, "error": dns.error,
                "blocked_24h": sum(dns.tenant_stats(t["id"])["blocked_24h"] for t in tj),
                "queries_24h": sum(dns.tenant_stats(t["id"])["queries_24h"] for t in tj),
                "filtering_tenants": sum(any(t["filters"].values()) for t in tj),
            },
            "server": {
                "endpoint": f"{settings.endpoint}:{settings.wg_port}", "interface": settings.wg_interface,
                "interface_up": wgm.interface_up(), "subnet": str(settings.wg_subnet),
                "address": str(settings.server_address), "public_key": get_setting(c, "server_public_key"),
                "tenant_prefix": settings.tenant_prefix,
            },
        }

    @app.get("/api/admin/tenants")
    def list_tenants(_: Admin, c: Conn):
        stats = wgm.stats()
        rows = c.execute("SELECT * FROM tenants ORDER BY name COLLATE NOCASE").fetchall()
        return [tenant_json(c, t, stats) for t in rows]

    @app.post("/api/admin/tenants", status_code=201)
    def create_tenant(body: TenantCreate, _: Admin, c: Conn):
        if username_taken(c, body.username):
            raise HTTPException(409, "Ese nombre de usuario ya existe")
        idx = wg.next_free_net_index(c, settings)
        if idx is None:
            raise HTTPException(409, "No quedan redes libres para nuevos clientes")
        max_devices = min(body.max_devices, wg.device_capacity(settings))
        cur = c.execute(
            """INSERT INTO tenants (name, username, password_hash, must_change, net_index, max_devices, notes, created_at)
               VALUES (?, ?, ?, 1, ?, ?, ?, ?)""",
            (body.name, body.username, security.hash_password(body.password), idx, max_devices,
             body.notes, int(time.time())),
        )
        c.commit()
        apply_wg()
        return tenant_json(c, tenant_or_404(c, cur.lastrowid), {})

    @app.get("/api/admin/tenants/{tenant_id}")
    def get_tenant(tenant_id: int, _: Admin, c: Conn):
        return tenant_json(c, tenant_or_404(c, tenant_id), wgm.stats())

    @app.patch("/api/admin/tenants/{tenant_id}")
    def update_tenant(tenant_id: int, body: TenantUpdate, _: Admin, c: Conn):
        t = tenant_or_404(c, tenant_id)
        if body.name is not None:
            c.execute("UPDATE tenants SET name = ? WHERE id = ?", (body.name, tenant_id))
        if body.notes is not None:
            c.execute("UPDATE tenants SET notes = ? WHERE id = ?", (body.notes, tenant_id))
        if body.max_devices is not None:
            count = c.execute("SELECT COUNT(*) FROM devices WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
            if body.max_devices < count:
                raise HTTPException(400, f"El cliente ya tiene {count} dispositivos")
            c.execute("UPDATE tenants SET max_devices = ? WHERE id = ?",
                      (min(body.max_devices, wg.device_capacity(settings)), tenant_id))
        if body.password is not None:
            c.execute("UPDATE tenants SET password_hash = ?, must_change = 1 WHERE id = ?",
                      (security.hash_password(body.password), tenant_id))
        if body.enabled is not None and bool(t["enabled"]) != body.enabled:
            c.execute("UPDATE tenants SET enabled = ? WHERE id = ?", (int(body.enabled), tenant_id))
        c.commit()
        apply_wg()
        return tenant_json(c, tenant_or_404(c, tenant_id), wgm.stats())

    @app.delete("/api/admin/tenants/{tenant_id}")
    def delete_tenant(tenant_id: int, _: Admin, c: Conn):
        tenant_or_404(c, tenant_id)
        c.execute("DELETE FROM tenants WHERE id = ?", (tenant_id,))
        c.commit()
        apply_wg()
        return {"ok": True}

    # ------------------------------------------------------------------ dispositivos
    @app.get("/api/devices")
    def list_devices(p: User, c: Conn, tenant_id: int | None = None):
        if not p.is_admin:
            tenant_id = p.id
        stats = wgm.stats()
        q = "SELECT * FROM devices" + (" WHERE tenant_id = ?" if tenant_id else "") + " ORDER BY created_at, id"
        rows = c.execute(q, (tenant_id,) if tenant_id else ()).fetchall()
        tenants = {t["id"]: t for t in c.execute("SELECT * FROM tenants")}
        return [device_json(d, tenants[d["tenant_id"]], stats) for d in rows]

    @app.post("/api/devices", status_code=201)
    def create_device(body: DeviceCreate, p: User, c: Conn):
        if p.is_admin:
            if body.tenant_id is None:
                raise HTTPException(400, "tenant_id es obligatorio")
            tenant_id = body.tenant_id
        else:
            tenant_id = p.id
        t = tenant_or_404(c, tenant_id)
        count = c.execute("SELECT COUNT(*) FROM devices WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
        if count >= t["max_devices"]:
            raise HTTPException(409, f"Límite de dispositivos alcanzado ({t['max_devices']})")
        ip = wg.next_free_ip(c, settings, t["net_index"])
        if ip is None:
            raise HTTPException(409, "No quedan IPs libres en la red del cliente")
        private, public = wg.generate_keypair()
        cur = c.execute(
            """INSERT INTO devices (tenant_id, name, ip, private_key, public_key, preshared_key, full_tunnel, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (tenant_id, body.name, ip, private, public, wg.generate_psk(), int(body.full_tunnel), int(time.time())),
        )
        c.commit()
        apply_wg()
        d = c.execute("SELECT * FROM devices WHERE id = ?", (cur.lastrowid,)).fetchone()
        return device_json(d, t, {})

    @app.patch("/api/devices/{device_id}")
    def update_device(device_id: int, body: DeviceUpdate, p: User, c: Conn):
        d = device_for(c, p, device_id)
        if body.name is not None:
            c.execute("UPDATE devices SET name = ? WHERE id = ?", (body.name, device_id))
        if body.enabled is not None:
            c.execute("UPDATE devices SET enabled = ? WHERE id = ?", (int(body.enabled), device_id))
        if body.full_tunnel is not None:
            c.execute("UPDATE devices SET full_tunnel = ? WHERE id = ?", (int(body.full_tunnel), device_id))
        if body.dns_filter is not None:
            c.execute("UPDATE devices SET dns_filter = ? WHERE id = ?", (int(body.dns_filter), device_id))
        c.commit()
        apply_wg()
        d = c.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        return device_json(d, tenant_or_404(c, d["tenant_id"]), wgm.stats())

    @app.delete("/api/devices/{device_id}")
    def delete_device(device_id: int, p: User, c: Conn):
        device_for(c, p, device_id)
        c.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        c.commit()
        apply_wg()
        return {"ok": True}

    def client_config(c: sqlite3.Connection, p: Principal, device_id: int) -> tuple[str, str]:
        d = device_for(c, p, device_id)
        t = tenant_or_404(c, d["tenant_id"])
        conf = wg.render_client_conf(settings, get_setting(c, "server_public_key") or "", t, d)
        slug = re.sub(r"[^A-Za-z0-9_-]+", "-", d["name"]).strip("-")[:15] or f"wg{d['id']}"
        return conf, slug

    @app.get("/api/devices/{device_id}/config")
    def device_config(device_id: int, p: User, c: Conn):
        conf, slug = client_config(c, p, device_id)
        return Response(conf, media_type="text/plain; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{slug}.conf"'})

    @app.get("/api/devices/{device_id}/qr.svg")
    def device_qr(device_id: int, p: User, c: Conn):
        conf, _ = client_config(c, p, device_id)
        buf = io.BytesIO()
        segno.make(conf, error="m").save(buf, kind="svg", scale=5, border=2, dark="#000", light="#fff")
        return Response(buf.getvalue(), media_type="image/svg+xml")

    # ------------------------------------------------------------------ filtros DNS
    def filters_tenant(p: Principal, tenant_id: int | None) -> int:
        if p.is_admin:
            if tenant_id is None:
                raise HTTPException(400, "tenant_id es obligatorio")
            return tenant_id
        return p.id

    def filters_json(c: sqlite3.Connection, tenant_id: int) -> dict:
        t = tenant_or_404(c, tenant_id)
        return {
            "tenant_id": t["id"],
            "filters": dnsfilter.parse_filters(t["dns_filters"]),
            "allowlist": dnsfilter.split_domains(t["dns_allow"]),
            "denylist": dnsfilter.split_domains(t["dns_deny"]),
            "stats": dns.tenant_stats(t["id"]),
            "resolver": {"enabled": settings.dns_enabled, "running": dns.running, "error": dns.error},
        }

    @app.get("/api/filters/catalog")
    def filters_catalog(_: User):
        lists = dns.lists.stats()
        return {
            "categories": [
                {"key": cat.key, "name": cat.name, "description": cat.description,
                 "sources": [src.name for src in cat.sources],
                 "domains": lists[cat.key]["domains"], "updated": lists[cat.key]["updated"]}
                for cat in dnsfilter.CATEGORIES
            ],
            "enabled": settings.dns_enabled, "running": dns.running,
        }

    @app.get("/api/filters")
    def get_filters(p: User, c: Conn, tenant_id: int | None = None):
        return filters_json(c, filters_tenant(p, tenant_id))

    @app.put("/api/filters")
    def put_filters(body: FiltersIn, p: User, c: Conn, tenant_id: int | None = None):
        if not settings.dns_enabled:
            raise HTTPException(409, "El filtrado DNS está desactivado en este servidor")
        tid = filters_tenant(p, tenant_id)
        tenant_or_404(c, tid)
        flags = {k: getattr(body, k) for k in dnsfilter.FILTER_KEYS}
        c.execute(
            "UPDATE tenants SET dns_filters = ?, dns_allow = ?, dns_deny = ? WHERE id = ?",
            (json.dumps(flags), "\n".join(body.allowlist), "\n".join(body.denylist), tid),
        )
        c.commit()
        apply_wg()
        return filters_json(c, tid)

    # ------------------------------------------------------------------ SPA
    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"ok": True}

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    sw_source = (STATIC_DIR / "sw.js").read_text().replace("__VERSION__", _static_version())

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})

    # PWA: el service worker y el manifest se sirven desde la raíz para que su
    # ámbito (scope) cubra toda la aplicación.
    @app.get("/sw.js", include_in_schema=False)
    def service_worker():
        return Response(sw_source, media_type="text/javascript",
                        headers={"Cache-Control": "no-cache", "Service-Worker-Allowed": "/"})

    @app.get("/manifest.webmanifest", include_in_schema=False)
    def manifest():
        return FileResponse(STATIC_DIR / "manifest.webmanifest", media_type="application/manifest+json",
                            headers={"Cache-Control": "no-cache"})

    return app

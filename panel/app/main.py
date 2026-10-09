"""API HTTP y servidor de la SPA del panel WireGuard Multi-Tenant."""

import asyncio
import hashlib
import ipaddress
import io
import json
import logging
import re
import socket
import sqlite3
import threading
import time
import unicodedata
import urllib.parse
from contextlib import asynccontextmanager
from dataclasses import dataclass
from types import SimpleNamespace
from pathlib import Path
from typing import Annotated

import segno
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

import bcrypt

from . import alerts, backup, caddy, dnsfilter, domains, forwards, history, members, monitor, passkeys, security, wg
from .config import Settings, load_settings
from .db import (LABEL_RE, Database, get_setting, make_hostname, name_in_use, set_setting,
                 unique_hostname, username_taken)

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
    max_forwards: int | None = Field(default=None, ge=0, le=100)
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
    kind: str = Field(default="device", pattern="^(device|router)$")
    lan_networks: list[str] = Field(default_factory=list, max_length=10)
    monitor: bool | None = None       # avisar si se desconecta (por defecto: sólo routers)
    member_id: int | None = None      # usuario del cliente al que pertenece (responsable/admin)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        return _clean_name(v)


class DeviceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=48)
    enabled: bool | None = None
    full_tunnel: bool | None = None
    dns_filter: bool | None = None
    hostname: str | None = Field(default=None, max_length=63)
    lan_networks: list[str] | None = Field(default=None, max_length=10)
    monitor: bool | None = None
    member_id: int | None = None      # 0 = sin asignar

    @field_validator("name")
    @classmethod
    def _name(cls, v: str | None) -> str | None:
        return None if v is None else _clean_name(v)


class ServiceIn(BaseModel):
    hostname: str = Field(min_length=4, max_length=253)
    target_ip: str = Field(min_length=7, max_length=15)
    target_port: int = Field(ge=1, le=65535)
    scheme: str = Field(default="http", pattern="^(http|https)$")
    auth_user: str = Field(default="", max_length=32)
    auth_password: str = Field(default="", max_length=128)
    tenant_id: int | None = None  # sólo admin


class ServiceUpdate(BaseModel):
    enabled: bool | None = None
    target_ip: str | None = Field(default=None, min_length=7, max_length=15)
    target_port: int | None = Field(default=None, ge=1, le=65535)
    scheme: str | None = Field(default=None, pattern="^(http|https)$")
    auth_user: str | None = Field(default=None, max_length=32)
    auth_password: str | None = Field(default=None, max_length=128)
    clear_auth: bool = False


class BackupIn(BaseModel):
    enabled: bool | None = None
    hour: int | None = Field(default=None, ge=0, le=23)
    keep: int | None = Field(default=None, ge=1, le=365)
    passphrase: str | None = Field(default=None, max_length=256)
    s3_endpoint: str | None = Field(default=None, max_length=300)
    s3_region: str | None = Field(default=None, max_length=64)
    s3_bucket: str | None = Field(default=None, max_length=63)
    s3_prefix: str | None = Field(default=None, max_length=200)
    s3_access_key: str | None = Field(default=None, max_length=200)
    s3_secret_key: str | None = Field(default=None, max_length=200)  # vacío = conservar
    clear_s3: bool = False


class EndpointIn(BaseModel):
    endpoint: str | None = Field(default=None, max_length=253)


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


def _dns_name(value: str, what: str = "Nombre") -> str:
    """Nombre relativo dentro de la red: una o varias etiquetas DNS («nas», «impresora.planta2»)."""
    name = value.strip().lower().rstrip(".")
    labels = name.split(".")
    if not name or len(name) > 100 or not all(LABEL_RE.match(x) for x in labels):
        raise HTTPException(422, f"{what} no válido: {value!r}. Usa letras, números y guiones (p. ej. portatil-ana)")
    return name


class RecordIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    ip: str = Field(min_length=7, max_length=15)


class UpstreamsIn(BaseModel):
    upstreams: list[str] = Field(default_factory=list, max_length=3)


class SuffixesIn(BaseModel):
    suffixes: list[str] = Field(default_factory=list, max_length=5)


class PasskeyRegisterIn(BaseModel):
    state: str = Field(max_length=64)
    credential: dict
    name: str = Field(default="", max_length=60)


class PasskeyLoginIn(BaseModel):
    state: str = Field(max_length=64)
    credential: dict


class SettingsIn(BaseModel):
    main_domain: str | None = Field(default=None, max_length=253)
    force_https: bool = False


class DomainIn(BaseModel):
    domain: str | None = Field(default=None, max_length=253)


def _probe(ip: str, port: int) -> dict:
    """¿Responde el equipo de destino de un servicio publicado? (conexión TCP desde el servidor)."""
    try:
        with socket.create_connection((ip, int(port)), timeout=3):
            return {"ok": True, "error": None}
    except OSError as exc:
        reason = "no responde (¿encendido y conectado a la VPN?)" if isinstance(exc, TimeoutError) else (exc.strerror or str(exc))
        return {"ok": False, "error": f"{ip}:{port} {reason}"}


def _clean_host(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    host = domains.normalize_host(value)
    if host is None:
        raise HTTPException(422, f"Dominio no válido: {value!r} (ejemplo: vpn.miempresa.com)")
    return host


@dataclass
class Principal:
    """Quién hace la petición.

    role: admin | tenant (responsable de un cliente) | member (usuario de un cliente).
    id: id en su tabla (admins, tenants o members). tenant_id: cliente al que pertenece.
    """
    role: str
    id: int
    username: str
    name: str
    must_change: bool
    tenant_id: int | None = None
    can_create: bool = True

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_member(self) -> bool:
        return self.role == "member"


ROLE_TABLE = {"admin": "admins", "tenant": "tenants", "member": "members"}


# --------------------------------------------------------------------------------- app
def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    database = Database(settings.data_dir / "panel.db")
    database.init(settings.admin_user, settings.admin_password, wg.generate_keypair)
    wgm = wg.WireGuardManager(settings, database)
    sessions = security.SessionManager(settings.session_secret, settings.session_hours * 3600)
    limiter = security.RateLimiter(limit=10, window=300)
    dns = dnsfilter.DnsFilter(settings, database)
    doms = domains.Domains(settings, database)
    keys = passkeys.Passkeys()
    proxy = caddy.CaddySync(settings, database, settings.caddy_admin, settings.acme_email)
    backups = backup.Backups(settings, database)
    mon = monitor.Monitor(settings, database, wgm, dns)
    notifier = alerts.Notifier(database)
    mon.listeners.append(notifier.on_monitor_events)
    backups.on_failure = notifier.on_backup_failed
    doms.seed_from_env(settings.panel_domain)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            wgm.apply()
        except Exception:  # noqa: BLE001 - el panel debe arrancar aunque falle la aplicación
            log.exception("No se pudo aplicar la configuración WireGuard al arrancar")
        if settings.dns_enabled:
            await dns.start()
        proxy.start()
        backups.start()
        mon.start()
        await asyncio.to_thread(notifier.start_telegram)
        yield
        notifier.stop_telegram()
        await mon.stop()
        await backups.stop()
        await proxy.stop()
        await dns.stop()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings, app.state.db, app.state.wg, app.state.dns = settings, database, wgm, dns
    app.state.domains = doms
    app.state.caddy = proxy
    app.state.backups = backups
    app.state.monitor = mon
    app.state.notifier = notifier

    # ------------------------------------------------------------------ middleware
    @app.middleware("http")
    async def guard(request: Request, call_next):
        # HTTPS forzado: el acceso directo por HTTP (http://IP:5000) se redirige al
        # dominio. Se exceptúan las peticiones locales sin proxy (healthchecks,
        # instalador y la consulta de Caddy a /internal/tls-ask).
        if not local_direct(request) and request.url.scheme != "https":
            with database.conn() as c:
                force, main = doms.force_https(c), doms.main_domain(c)
                host = domains.host_of(request.headers.get("host"))
                target = host if doms.registered(c, host) else main
            if force and target:
                url = f"https://{target}{request.url.path}" + (f"?{request.url.query}" if request.url.query else "")
                return RedirectResponse(url, status_code=308)
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

    def local_direct(request: Request) -> bool:
        """Conexión desde el propio servidor que no viene a través de Caddy."""
        client = request.client.host if request.client else ""
        return client in ("127.0.0.1", "::1") and "x-forwarded-for" not in request.headers

    # ------------------------------------------------------------------ dependencias
    def db_conn():
        with database.conn() as c:
            yield c

    Conn = Annotated[sqlite3.Connection, Depends(db_conn)]

    def principal(request: Request, c: Conn) -> Principal:
        data = sessions.load(request.cookies.get(sessions.COOKIE))
        if not data:
            raise HTTPException(401, "Sesión no válida")
        tenant_id, can_create = None, True
        if data["role"] == "admin":
            row = c.execute("SELECT * FROM admins WHERE id = ?", (data["uid"],)).fetchone()
            name = row["username"] if row else ""
        elif data["role"] == "member":
            row = c.execute("""SELECT m.* FROM members m JOIN tenants t ON t.id = m.tenant_id
                               WHERE m.id = ? AND m.enabled = 1 AND t.enabled = 1""", (data["uid"],)).fetchone()
            name = row["name"] if row else ""
            if row:
                tenant_id, can_create = row["tenant_id"], bool(row["can_create"])
        else:
            row = c.execute("SELECT * FROM tenants WHERE id = ? AND enabled = 1", (data["uid"],)).fetchone()
            name = row["name"] if row else ""
            tenant_id = row["id"] if row else None
        if not row or security.password_version(row["password_hash"]) != data.get("pwv"):
            raise HTTPException(401, "Sesión caducada")
        return Principal(data["role"], row["id"], row["username"], name, bool(row["must_change"]), tenant_id, can_create)

    AnyUser = Annotated[Principal, Depends(principal)]

    def ready(p: AnyUser) -> Principal:
        if p.must_change:
            raise HTTPException(403, "password_change_required")
        return p

    # Anyone: cualquier sesión (también usuarios de un cliente). User: admin o
    # responsable del cliente; los usuarios de un cliente sólo llegan a lo que
    # usa Anyone (sus dispositivos, su cuenta, su historial y sus avisos).
    Anyone = Annotated[Principal, Depends(ready)]

    def manager(p: Anyone) -> Principal:
        if p.is_member:
            raise HTTPException(403, "Sólo el responsable de la cuenta puede hacer esto")
        return p

    User = Annotated[Principal, Depends(manager)]

    def admin(p: User) -> Principal:
        if not p.is_admin:
            raise HTTPException(403, "Sólo administradores")
        return p

    Admin = Annotated[Principal, Depends(admin)]

    def set_session(request: Request, response: Response, role: str, uid: int, password_hash: str) -> None:
        response.set_cookie(
            sessions.COOKIE, sessions.dump(role, uid, security.password_version(password_hash)),
            max_age=sessions.max_age, httponly=True, samesite="strict", path="/",
            secure=settings.cookie_secure or request.url.scheme == "https",
        )

    # ------------------------------------------------------------------ helpers
    def tenant_or_404(c: sqlite3.Connection, tenant_id: int) -> sqlite3.Row:
        row = c.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Cliente no encontrado")
        return row

    def device_for(c: sqlite3.Connection, p: Principal, device_id: int) -> sqlite3.Row:
        row = c.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if (not row or (not p.is_admin and row["tenant_id"] != p.tenant_id)
                or (p.is_member and row["member_id"] != p.id)):
            raise HTTPException(404, "Dispositivo no encontrado")
        return row

    def visible_devices(p: Principal, c: sqlite3.Connection) -> set[int] | None:
        """Dispositivos que puede ver un usuario de cliente (None = sin restricción)."""
        if not p.is_member:
            return None
        return {r["id"] for r in c.execute("SELECT id FROM devices WHERE member_id = ?", (p.id,))}

    def member_names(c: sqlite3.Connection, tenant_id: int) -> dict[int, str]:
        return {r["id"]: r["name"] for r in c.execute("SELECT id, name FROM members WHERE tenant_id = ?", (tenant_id,))}

    def device_json(d: sqlite3.Row, tenant: sqlite3.Row, stats: dict, members: dict | None = None) -> dict:
        st = stats.get(d["public_key"], {})
        return {
            "monitor": bool(d["monitor"]), "member_id": d["member_id"],
            "member_name": (members or {}).get(d["member_id"]) if d["member_id"] else None,
            "id": d["id"], "tenant_id": d["tenant_id"], "tenant_name": tenant["name"],
            "name": d["name"], "ip": d["ip"], "public_key": d["public_key"],
            "full_tunnel": bool(d["full_tunnel"]), "enabled": bool(d["enabled"]),
            "dns_filter": bool(d["dns_filter"]), "hostname": d["hostname"],
            "kind": d["kind"], "lan_networks": wg.parse_lans(d["lan_networks"]),
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
            "max_devices": t["max_devices"], "max_forwards": t["max_forwards"],
            "enabled": bool(t["enabled"]), "notes": t["notes"],
            "created_at": t["created_at"], "must_change": bool(t["must_change"]),
            "filters": dnsfilter.parse_filters(t["dns_filters"]),
            "device_count": len(dj), "online_count": sum(d["online"] for d in dj),
            "rx": sum(d["rx"] for d in dj), "tx": sum(d["tx"] for d in dj),
        }

    def clean_lans(c: sqlite3.Connection, values: list[str], device_id: int | None = None) -> list[str]:
        """Redes LAN de un router: privadas, sin solaparse con el túnel, el servidor ni otros routers.

        Las rutas del servidor son globales, así que dos clientes no pueden publicar la
        misma LAN (p. ej. 192.168.1.0/24): se rechaza sin revelar quién la usa.
        """
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        taken = []
        for r in c.execute("SELECT id, lan_networks FROM devices WHERE kind = 'router'"):
            if r["id"] != device_id:
                taken += [ipaddress.ip_network(x) for x in wg.parse_lans(r["lan_networks"])]
        host_nets = wgm.host_networks()
        out: list[ipaddress.IPv4Network] = []
        for raw in values:
            try:
                net = ipaddress.ip_network(raw.strip(), strict=False)
            except ValueError:
                raise HTTPException(422, f"Red no válida: {raw!r} (ejemplo: 192.168.88.0/24)") from None
            if not isinstance(net, ipaddress.IPv4Network) or not 8 <= net.prefixlen <= 30:
                raise HTTPException(422, f"{raw}: usa una red IPv4 entre /8 y /30")
            if not (net.is_private or net.subnet_of(cgnat)) or net.is_loopback or net.is_link_local:
                raise HTTPException(422, f"{net}: sólo se admiten redes privadas (192.168.x, 172.16-31.x, 10.x)")
            if net.overlaps(settings.wg_subnet):
                raise HTTPException(422, f"{net} se solapa con la red de la VPN ({settings.wg_subnet})")
            if any(net.overlaps(h) for h in host_nets):
                raise HTTPException(409, f"{net} se solapa con una red del propio servidor; elige otra")
            if any(net.overlaps(t) for t in taken):
                raise HTTPException(409, f"{net} ya la usa otra red de la plataforma; elige otro rango "
                                         "(p. ej. 192.168.123.0/24)")
            if any(net.overlaps(o) for o in out):
                raise HTTPException(422, f"{net} está repetida o se solapa con otra de la lista")
            out.append(net)
        return [str(n) for n in out]

    def push_caddy() -> None:
        if proxy.enabled:
            threading.Thread(target=proxy.push, daemon=True).start()

    def apply_wg() -> None:
        dns.reload_policies()
        push_caddy()
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
        if not row:
            role, row = "member", c.execute(
                "SELECT * FROM members WHERE username = ? COLLATE NOCASE", (body.username,)
            ).fetchone()
        if not row or not security.verify_password(body.password, row["password_hash"]):
            limiter.hit(key)
            raise HTTPException(401, "Usuario o contraseña incorrectos")
        limiter.reset(key)
        return finish_login(request, response, c, role, row)

    def finish_login(request: Request, response: Response, c: sqlite3.Connection, role: str, row: sqlite3.Row) -> dict:
        """Comprobaciones comunes a contraseña y llave biométrica, y apertura de sesión."""
        tenant_id = row["id"] if role == "tenant" else row["tenant_id"] if role == "member" else None
        if role == "tenant" and not row["enabled"]:
            raise HTTPException(403, "Cuenta deshabilitada. Contacte con su proveedor.")
        if role == "member":
            t = c.execute("SELECT enabled FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
            if not row["enabled"] or not t or not t["enabled"]:
                raise HTTPException(403, "Cuenta deshabilitada. Contacte con el responsable de su empresa.")
            c.execute("UPDATE members SET last_login = ? WHERE id = ?", (int(time.time()), row["id"]))
        # En el dominio propio de un cliente sólo pueden entrar ese cliente y sus usuarios.
        owner = doms.tenant_for_host(c, domains.host_of(request.headers.get("host")))
        if owner is not None and tenant_id != owner["id"]:
            raise HTTPException(403, "Esta cuenta no puede acceder desde este dominio")
        set_session(request, response, role, row["id"], row["password_hash"])
        return {"role": role, "must_change": bool(row["must_change"])}

    @app.post("/api/auth/logout")
    def logout(response: Response):
        response.delete_cookie(sessions.COOKIE, path="/")
        return {"ok": True}

    @app.get("/api/me")
    def me(p: AnyUser, c: Conn):
        data = {"role": p.role, "id": p.id, "username": p.username, "name": p.name, "must_change": p.must_change}
        if not p.is_admin:
            t = tenant_or_404(c, p.tenant_id)
            data.update(network=str(wg.tenant_network(settings, t["net_index"])), max_devices=t["max_devices"],
                        tenant_id=t["id"], tenant_name=t["name"])
        if p.is_member:
            data.update(can_create=p.can_create)
        return data

    @app.post("/api/me/password")
    def change_password(body: PasswordIn, p: AnyUser, request: Request, response: Response, c: Conn):
        table = ROLE_TABLE[p.role]
        row = c.execute(f"SELECT password_hash FROM {table} WHERE id = ?", (p.id,)).fetchone()
        if not security.verify_password(body.current, row["password_hash"]):
            raise HTTPException(400, "La contraseña actual no es correcta")
        if body.new == body.current:
            raise HTTPException(400, "La nueva contraseña debe ser distinta")
        new_hash = security.hash_password(body.new)
        c.execute(f"UPDATE {table} SET password_hash = ?, must_change = 0 WHERE id = ?", (new_hash, p.id))
        set_session(request, response, p.role, p.id, new_hash)  # el resto de sesiones quedan invalidadas
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
                "endpoint": f"{wg.endpoint_host(c, settings)}:{settings.wg_port}", "interface": settings.wg_interface,
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
        if body.max_forwards is not None:
            c.execute("UPDATE tenants SET max_forwards = ? WHERE id = ?", (body.max_forwards, tenant_id))
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
        for table in ("passkeys", "alert_channels", "alert_prefs"):
            c.execute(f"""DELETE FROM {table} WHERE role = 'member'
                          AND user_id IN (SELECT id FROM members WHERE tenant_id = ?)""", (tenant_id,))
            c.execute(f"DELETE FROM {table} WHERE role = 'tenant' AND user_id = ?", (tenant_id,))
        c.execute("DELETE FROM tenants WHERE id = ?", (tenant_id,))
        c.execute("DELETE FROM passkeys WHERE role = 'tenant' AND user_id = ?", (tenant_id,))
        c.commit()
        apply_wg()
        return {"ok": True}

    # ------------------------------------------------------------------ dispositivos
    @app.get("/api/devices")
    def list_devices(p: Anyone, c: Conn, tenant_id: int | None = None):
        if not p.is_admin:
            tenant_id = p.tenant_id
        stats = wgm.stats()
        q = "SELECT * FROM devices" + (" WHERE tenant_id = ?" if tenant_id else "") + " ORDER BY created_at, id"
        rows = c.execute(q, (tenant_id,) if tenant_id else ()).fetchall()
        if p.is_member:
            rows = [d for d in rows if d["member_id"] == p.id]
        tenants = {t["id"]: t for t in c.execute("SELECT * FROM tenants")}
        names = {r["id"]: r["name"] for r in c.execute("SELECT id, name FROM members")}
        return [device_json(d, tenants[d["tenant_id"]], stats, names) for d in rows]

    def clean_member(c: sqlite3.Connection, tenant_id: int, member_id: int | None) -> int | None:
        if not member_id:
            return None
        if not c.execute("SELECT 1 FROM members WHERE id = ? AND tenant_id = ?", (member_id, tenant_id)).fetchone():
            raise HTTPException(422, "Ese usuario no pertenece a este cliente")
        return member_id

    @app.post("/api/devices", status_code=201)
    def create_device(body: DeviceCreate, p: Anyone, c: Conn):
        if p.is_admin:
            if body.tenant_id is None:
                raise HTTPException(400, "tenant_id es obligatorio")
            tenant_id = body.tenant_id
        else:
            tenant_id = p.tenant_id
        if p.is_member:
            if not p.can_create:
                raise HTTPException(403, "Pide al responsable de tu empresa que añada el dispositivo")
            if body.kind == "router":
                raise HTTPException(403, "Sólo el responsable de la cuenta puede añadir routers")
            member_id = p.id
        else:
            member_id = clean_member(c, tenant_id, body.member_id)
        t = tenant_or_404(c, tenant_id)
        count = c.execute("SELECT COUNT(*) FROM devices WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
        if count >= t["max_devices"]:
            raise HTTPException(409, f"Límite de dispositivos alcanzado ({t['max_devices']})")
        ip = wg.next_free_ip(c, settings, t["net_index"])
        if ip is None:
            raise HTTPException(409, "No quedan IPs libres en la red del cliente")
        private, public = wg.generate_keypair()
        hostname = unique_hostname(c, tenant_id, make_hostname(body.name))
        is_router = body.kind == "router"
        lans = clean_lans(c, body.lan_networks) if is_router else []
        if is_router and not lans:
            raise HTTPException(422, "Indica al menos una red LAN del router (p. ej. 192.168.88.0/24)")
        cur = c.execute(
            """INSERT INTO devices (tenant_id, name, ip, private_key, public_key, preshared_key, full_tunnel,
                                    created_at, hostname, kind, lan_networks, monitor, member_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (tenant_id, body.name, ip, private, public, wg.generate_psk(), int(body.full_tunnel and not is_router),
             int(time.time()), hostname, body.kind, " ".join(lans),
             int(is_router if body.monitor is None else body.monitor), member_id),
        )
        c.commit()
        apply_wg()
        d = c.execute("SELECT * FROM devices WHERE id = ?", (cur.lastrowid,)).fetchone()
        return device_json(d, t, {}, member_names(c, tenant_id))

    @app.patch("/api/devices/{device_id}")
    def update_device(device_id: int, body: DeviceUpdate, p: Anyone, c: Conn):
        d = device_for(c, p, device_id)
        if p.is_member and any(v is not None for v in (body.lan_networks, body.hostname, body.dns_filter, body.member_id)):
            raise HTTPException(403, "Sólo el responsable de la cuenta puede cambiar eso")
        if body.member_id is not None:
            c.execute("UPDATE devices SET member_id = ? WHERE id = ?", (clean_member(c, d["tenant_id"], body.member_id), device_id))
        if body.monitor is not None:
            c.execute("UPDATE devices SET monitor = ? WHERE id = ?", (int(body.monitor), device_id))
        if body.lan_networks is not None:
            if d["kind"] != "router":
                raise HTTPException(422, "Sólo los routers tienen redes LAN")
            lans = clean_lans(c, body.lan_networks, device_id)
            if not lans:
                raise HTTPException(422, "Un router necesita al menos una red LAN")
            c.execute("UPDATE devices SET lan_networks = ? WHERE id = ?", (" ".join(lans), device_id))
        if body.hostname is not None:
            hostname = _dns_name(body.hostname, "Nombre de red")
            if "." in hostname:
                raise HTTPException(422, "El nombre de red de un dispositivo no puede contener puntos")
            if name_in_use(c, d["tenant_id"], hostname, exclude_device=device_id):
                raise HTTPException(409, f"El nombre «{hostname}» ya está en uso en esta red")
            c.execute("UPDATE devices SET hostname = ? WHERE id = ?", (hostname, device_id))
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
        return device_json(d, tenant_or_404(c, d["tenant_id"]), wgm.stats(), member_names(c, d["tenant_id"]))

    @app.delete("/api/devices/{device_id}")
    def delete_device(device_id: int, p: Anyone, c: Conn):
        device_for(c, p, device_id)
        c.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        c.commit()
        apply_wg()
        return {"ok": True}

    def client_config(c: sqlite3.Connection, p: Principal, device_id: int) -> tuple[str, str]:
        return render_config(c, device_for(c, p, device_id))

    def render_config(c: sqlite3.Connection, d: sqlite3.Row) -> tuple[str, str]:
        t = tenant_or_404(c, d["tenant_id"])
        conf = wg.render_client_conf(settings, get_setting(c, "server_public_key") or "", t, d,
                                     search=dnsfilter.parse_suffixes(get_setting(c, "dns_suffixes")),
                                     endpoint=wg.endpoint_host(c, settings),
                                     lans=wg.tenant_lans(c, t["id"], exclude_device=d["id"]))
        plain = unicodedata.normalize("NFKD", d["name"]).encode("ascii", "ignore").decode()  # «Matías» -> «Matias»
        slug = re.sub(r"[^A-Za-z0-9_-]+", "-", plain).strip("-")[:15] or f"wg{d['id']}"
        return conf, slug

    @app.get("/api/devices/{device_id}/config")
    def device_config(device_id: int, p: Anyone, c: Conn):
        conf, slug = client_config(c, p, device_id)
        return Response(conf, media_type="text/plain; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{slug}.conf"'})

    @app.get("/api/devices/{device_id}/mikrotik")
    def device_mikrotik(device_id: int, p: Anyone, c: Conn):
        d = device_for(c, p, device_id)
        t = tenant_or_404(c, d["tenant_id"])
        script = wg.render_mikrotik(settings, get_setting(c, "server_public_key") or "", t, d,
                                    endpoint=wg.endpoint_host(c, settings),
                                    lans=wg.tenant_lans(c, t["id"], exclude_device=d["id"]))
        return Response(script, media_type="text/plain; charset=utf-8")

    # ------------------------------------------------------------------ copias de seguridad
    def backup_state() -> dict:
        cfg = backups.config()
        return {
            "enabled": cfg["backup_enabled"] == "1", "hour": int(cfg["backup_hour"]), "keep": int(cfg["backup_keep"]),
            "has_passphrase": len(cfg["passphrase"]) >= 12, "last": cfg["last"], "backups": backups.list(),
            "timezone": time.strftime("%Z"),
            "s3": {"endpoint": cfg["s3_endpoint"], "region": cfg["s3_region"], "bucket": cfg["s3_bucket"],
                   "prefix": cfg["s3_prefix"], "access_key": cfg["s3_access_key"], "secret_set": bool(cfg["s3_secret_key"]),
                   "configured": backup.s3_configured(cfg)},
        }

    def clean_s3(body: BackupIn, cfg: dict) -> dict:
        new = {k: cfg[k] for k in backup.DEFAULTS if k.startswith("s3_")}
        for k in ("s3_endpoint", "s3_region", "s3_bucket", "s3_prefix", "s3_access_key"):
            v = getattr(body, k)
            if v is not None:
                new[k] = v.strip()
        if body.s3_secret_key:
            new["s3_secret_key"] = body.s3_secret_key.strip()
        if new["s3_endpoint"]:
            url = urllib.parse.urlsplit(new["s3_endpoint"] if "://" in new["s3_endpoint"] else "https://" + new["s3_endpoint"])
            if url.scheme not in ("http", "https") or not url.hostname or url.query or url.fragment:
                raise HTTPException(422, "Endpoint S3 no válido (p. ej. https://s3.eu-west-1.amazonaws.com)")
            new["s3_endpoint"] = f"{url.scheme}://{url.netloc}{url.path.rstrip('/')}"
        if new["s3_bucket"] and not re.fullmatch(r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]", new["s3_bucket"]):
            raise HTTPException(422, "Nombre de bucket no válido")
        if not re.fullmatch(r"[A-Za-z0-9._/\-]{0,200}", new["s3_prefix"]):
            raise HTTPException(422, "Prefijo no válido: letras, números, . _ - /")
        if not re.fullmatch(r"[a-z0-9\-]{1,64}", new["s3_region"] or "auto"):
            raise HTTPException(422, "Región no válida (p. ej. eu-west-1 o auto)")
        new["s3_region"] = new["s3_region"] or "auto"
        return new

    @app.get("/api/admin/backup")
    def get_backup(_: Admin):
        return backup_state()

    @app.put("/api/admin/backup")
    def put_backup(body: BackupIn, _: Admin):
        cfg = backups.config()
        values: dict = {}
        if body.passphrase is not None:
            if len(body.passphrase) < 12:
                raise HTTPException(422, "La frase de paso debe tener al menos 12 caracteres")
            values["backup_passphrase"] = body.passphrase
        if body.enabled is not None:
            if body.enabled and len(cfg["passphrase"]) < 12 and "backup_passphrase" not in values:
                raise HTTPException(422, "Define primero la frase de paso de las copias")
            values["backup_enabled"] = "1" if body.enabled else "0"
        if body.hour is not None:
            values["backup_hour"] = body.hour
        if body.keep is not None:
            values["backup_keep"] = body.keep
        if body.clear_s3:
            values.update({k: backup.DEFAULTS[k] for k in backup.DEFAULTS if k.startswith("s3_")})
        else:
            values.update(clean_s3(body, cfg))
        backups.save_config(values)
        if body.keep is not None:
            backups.prune(body.keep)
        return backup_state()

    @app.post("/api/admin/backup/run")
    async def run_backup(_: Admin):
        try:
            result = await backups.run_now("manual")
        except backup.BackupError as exc:
            raise HTTPException(409, str(exc)) from None
        return {**backup_state(), "result": result}

    @app.post("/api/admin/backup/test-s3")
    async def test_s3(body: BackupIn, _: Admin):
        cfg = {**backups.config(), **clean_s3(body, backups.config())}
        if not backup.s3_configured(cfg):
            raise HTTPException(422, "Completa endpoint, bucket, access key y secret key")
        try:
            await asyncio.to_thread(backups.test_s3, cfg)
        except backup.BackupError as exc:
            raise HTTPException(409, str(exc)) from None
        return {"ok": True}

    @app.get("/api/admin/backups/{name}")
    def download_backup(name: str, _: Admin):
        try:
            path = backups.path(name)
        except backup.BackupError as exc:
            raise HTTPException(404, str(exc)) from None
        return FileResponse(path, media_type="application/octet-stream", filename=name)

    @app.delete("/api/admin/backups/{name}")
    def delete_backup(name: str, _: Admin):
        try:
            backups.path(name).unlink()
        except backup.BackupError as exc:
            raise HTTPException(404, str(exc)) from None
        return backup_state()

    @app.get("/api/admin/wg-settings")
    def get_wg_settings(_: Admin, c: Conn):
        return {"endpoint": get_setting(c, "wg_endpoint") or "", "default": settings.endpoint,
                "effective": wg.endpoint_host(c, settings), "port": settings.wg_port}

    @app.put("/api/admin/wg-settings")
    def put_wg_settings(body: EndpointIn, admin_: Admin, c: Conn):
        raw = (body.endpoint or "").strip().lower()
        if raw:
            try:
                raw = str(ipaddress.ip_address(raw))
            except ValueError:
                host = domains.normalize_host(raw)
                if host is None:
                    raise HTTPException(422, f"Endpoint no válido: {body.endpoint!r} (IP o nombre, p. ej. wg.tudominio.com)")
                raw = host
        set_setting(c, "wg_endpoint", raw)
        c.commit()
        return get_wg_settings(admin_, c)

    @app.get("/api/devices/{device_id}/qr.svg")
    def device_qr(device_id: int, p: Anyone, c: Conn):
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

    # ------------------------------------------------------------------ llaves biométricas (passkeys)
    def rp_or_400(request: Request) -> passkeys.RelyingParty:
        try:
            return passkeys.relying_party(request)
        except passkeys.PasskeyError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/api/passkeys")
    def list_passkeys(request: Request, p: Anyone, c: Conn):
        try:
            current = passkeys.relying_party(request).rp_id
        except passkeys.PasskeyError:
            current = None
        rows = c.execute("SELECT id, name, rp_id, created_at, last_used_at FROM passkeys WHERE role = ? AND user_id = ?"
                         " ORDER BY created_at", (p.role, p.id)).fetchall()
        return {"available": current is not None, "rp_id": current,
                "passkeys": [dict(r) | {"current": r["rp_id"] == current} for r in rows]}

    @app.post("/api/passkeys/register/options")
    def passkey_register_options(request: Request, p: Anyone, c: Conn):
        rp = rp_or_400(request)
        try:
            state, options = keys.registration_options(c, rp, branding_for(c, request)["title"], p.role, p.id,
                                                       p.username, p.name or p.username)
        except passkeys.PasskeyError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"state": state, "options": json.loads(options)}

    @app.post("/api/passkeys/register/verify", status_code=201)
    def passkey_register_verify(body: PasskeyRegisterIn, request: Request, p: Anyone, c: Conn):
        rp = rp_or_400(request)
        try:
            keys.register(c, rp, body.state, body.credential, p.role, p.id, body.name.strip())
        except passkeys.PasskeyError as exc:
            raise HTTPException(400, str(exc)) from exc
        return list_passkeys(request, p, c)

    @app.delete("/api/passkeys/{passkey_id}")
    def delete_passkey(passkey_id: int, request: Request, p: Anyone, c: Conn):
        cur = c.execute("DELETE FROM passkeys WHERE id = ? AND role = ? AND user_id = ?", (passkey_id, p.role, p.id))
        if cur.rowcount == 0:
            raise HTTPException(404, "Llave no encontrada")
        return list_passkeys(request, p, c)

    @app.post("/api/passkeys/login/options")
    def passkey_login_options(request: Request):
        state, options = keys.authentication_options(rp_or_400(request))
        return {"state": state, "options": json.loads(options)}

    @app.post("/api/passkeys/login/verify")
    def passkey_login_verify(body: PasskeyLoginIn, request: Request, response: Response, c: Conn):
        key = request.client.host if request.client else "unknown"
        if limiter.blocked(key):
            raise HTTPException(429, "Demasiados intentos. Espere unos minutos.")
        rp = rp_or_400(request)
        try:
            pk = keys.authenticate(c, rp, body.state, body.credential)
        except passkeys.PasskeyError as exc:
            limiter.hit(key)
            raise HTTPException(401, str(exc)) from exc
        row = c.execute(f"SELECT * FROM {ROLE_TABLE[pk['role']]} WHERE id = ?", (pk["user_id"],)).fetchone()
        if row is None:
            raise HTTPException(401, "La cuenta de esta llave ya no existe")
        limiter.reset(key)
        c.commit()  # contador de firmas y último uso
        return finish_login(request, response, c, pk["role"], row)

    # ------------------------------------------------------------------ servicios publicados (Caddy)
    def service_json(c: sqlite3.Connection, r: sqlite3.Row) -> dict:
        dev = c.execute("SELECT name, hostname FROM devices WHERE tenant_id = ? AND ip = ?",
                        (r["tenant_id"], r["target_ip"])).fetchone()
        return {
            "id": r["id"], "tenant_id": r["tenant_id"], "hostname": r["hostname"],
            "target_ip": r["target_ip"], "target_port": r["target_port"], "scheme": r["scheme"],
            "protected": bool(r["auth_hash"]), "auth_user": r["auth_user"], "enabled": bool(r["enabled"]),
            "created_at": r["created_at"], "target_name": dev["name"] if dev else None,
        }

    def service_for(c: sqlite3.Connection, p: Principal, service_id: int) -> sqlite3.Row:
        row = c.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()
        if not row or (not p.is_admin and row["tenant_id"] != p.id):
            raise HTTPException(404, "Servicio no encontrado")
        return row

    def clean_target(c: sqlite3.Connection, tenant_id: int, raw: str) -> str:
        """El destino debe estar en la red del cliente o en la LAN de uno de sus routers."""
        t = tenant_or_404(c, tenant_id)
        try:
            ip = ipaddress.IPv4Address(raw.strip())
        except ValueError:
            raise HTTPException(422, f"IP no válida: {raw!r}") from None
        allowed = [wg.tenant_network(settings, t["net_index"])]
        for r in c.execute("SELECT lan_networks FROM devices WHERE tenant_id = ? AND kind = 'router'", (tenant_id,)):
            allowed += [ipaddress.ip_network(x) for x in wg.parse_lans(r["lan_networks"])]
        if not any(ip in n for n in allowed):
            nets = ", ".join(str(n) for n in allowed)
            raise HTTPException(422, f"{ip} no está en tu red ({nets})")
        return str(ip)

    def clean_auth(user: str, password: str) -> tuple[str, str]:
        user = user.strip()
        if not user and not password:
            return "", ""
        if not caddy.USER_RE.match(user):
            raise HTTPException(422, "Usuario no válido: letras, números, . _ - (máx. 32)")
        if len(password) < 8:
            raise HTTPException(422, "La contraseña del servicio debe tener al menos 8 caracteres")
        return user, bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()

    def services_tenant(p: Principal, tenant_id: int | None) -> int:
        if p.is_admin:
            if tenant_id is None:
                raise HTTPException(400, "tenant_id es obligatorio")
            return tenant_id
        return p.id

    @app.get("/api/services")
    def list_services(p: User, c: Conn, tenant_id: int | None = None):
        tid = services_tenant(p, tenant_id)
        t = tenant_or_404(c, tid)
        rows = c.execute("SELECT * FROM services WHERE tenant_id = ? ORDER BY hostname", (tid,)).fetchall()
        lans = [str(wg.tenant_network(settings, t["net_index"]))] + wg.tenant_lans(c, tid)
        return {"enabled": proxy.enabled, "error": proxy.last_error, "server_ips": sorted(doms.expected_ips()),
                "networks": lans, "services": [service_json(c, r) for r in rows]}

    @app.post("/api/services", status_code=201)
    def create_service(body: ServiceIn, p: User, c: Conn):
        if not proxy.enabled:
            raise HTTPException(409, "Los servicios publicados requieren el HTTPS automático (ENABLE_HTTPS=true)")
        tid = body.tenant_id if p.is_admin else p.id
        if tid is None:
            raise HTTPException(400, "tenant_id es obligatorio")
        tenant_or_404(c, tid)
        host = _clean_host(body.hostname)
        if not host:
            raise HTTPException(422, "Indica el nombre del servicio (p. ej. nas.tuempresa.com)")
        if doms.taken(c, host):
            raise HTTPException(409, "Ese nombre ya está en uso")
        if c.execute("SELECT COUNT(*) FROM services WHERE tenant_id = ?", (tid,)).fetchone()[0] >= 20:
            raise HTTPException(409, "Máximo 20 servicios por cliente")
        target = clean_target(c, tid, body.target_ip)
        user, hashed = clean_auth(body.auth_user, body.auth_password)
        cur = c.execute(
            """INSERT INTO services (tenant_id, hostname, target_ip, target_port, scheme, auth_user, auth_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (tid, host, target, body.target_port, body.scheme, user, hashed, int(time.time())),
        )
        c.commit()
        push_caddy()
        return service_json(c, c.execute("SELECT * FROM services WHERE id = ?", (cur.lastrowid,)).fetchone())

    @app.patch("/api/services/{service_id}")
    def update_service(service_id: int, body: ServiceUpdate, p: User, c: Conn):
        r = service_for(c, p, service_id)
        if body.target_ip is not None:
            c.execute("UPDATE services SET target_ip = ? WHERE id = ?", (clean_target(c, r["tenant_id"], body.target_ip), service_id))
        if body.target_port is not None:
            c.execute("UPDATE services SET target_port = ? WHERE id = ?", (body.target_port, service_id))
        if body.scheme is not None:
            c.execute("UPDATE services SET scheme = ? WHERE id = ?", (body.scheme, service_id))
        if body.enabled is not None:
            c.execute("UPDATE services SET enabled = ? WHERE id = ?", (int(body.enabled), service_id))
        if body.clear_auth:
            c.execute("UPDATE services SET auth_user = '', auth_hash = '' WHERE id = ?", (service_id,))
        elif body.auth_password:
            user, hashed = clean_auth(body.auth_user if body.auth_user is not None else r["auth_user"], body.auth_password)
            c.execute("UPDATE services SET auth_user = ?, auth_hash = ? WHERE id = ?", (user, hashed, service_id))
        c.commit()
        push_caddy()
        return service_json(c, c.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone())

    @app.delete("/api/services/{service_id}")
    def delete_service(service_id: int, p: User, c: Conn):
        service_for(c, p, service_id)
        c.execute("DELETE FROM services WHERE id = ?", (service_id,))
        c.commit()
        push_caddy()
        return {"ok": True}

    @app.get("/api/services/{service_id}/status")
    async def service_status(service_id: int, p: User, c: Conn):
        r = service_for(c, p, service_id)
        st = await asyncio.to_thread(doms.status, r["hostname"], True)
        st["target"] = await asyncio.to_thread(_probe, r["target_ip"], r["target_port"])
        return st

    # ------------------------------------------------------------------ DNS propio de cada cliente
    def zone_json(c: sqlite3.Connection, tenant_id: int) -> dict:
        t = tenant_or_404(c, tenant_id)
        suffixes = dnsfilter.parse_suffixes(get_setting(c, "dns_suffixes"))
        devices = c.execute("SELECT id, name, hostname, ip, enabled FROM devices WHERE tenant_id = ? ORDER BY hostname",
                            (tenant_id,)).fetchall()
        records = c.execute("SELECT id, name, ip FROM dns_records WHERE tenant_id = ? ORDER BY name", (tenant_id,)).fetchall()
        return {
            "tenant_id": t["id"], "network": str(wg.tenant_network(settings, t["net_index"])),
            "server": str(settings.server_address.ip), "suffixes": suffixes,
            "devices": [dict(d) | {"enabled": bool(d["enabled"])} for d in devices],
            "records": [dict(r) for r in records],
            "upstreams": dnsfilter.parse_suffixes(t["dns_upstream"]),
            "default_upstreams": settings.dns_upstreams,
            "resolver": {"enabled": settings.dns_enabled, "running": dns.running},
        }

    @app.get("/api/dns-zone")
    def get_zone(p: User, c: Conn, tenant_id: int | None = None):
        return zone_json(c, filters_tenant(p, tenant_id))

    @app.post("/api/dns-zone/records", status_code=201)
    def add_record(body: RecordIn, p: User, c: Conn, tenant_id: int | None = None):
        tid = filters_tenant(p, tenant_id)
        tenant_or_404(c, tid)
        name = _dns_name(body.name)
        try:
            ip = str(ipaddress.IPv4Address(body.ip.strip()))
        except ValueError:
            raise HTTPException(422, f"IP no válida: {body.ip!r}") from None
        if name_in_use(c, tid, name):
            raise HTTPException(409, f"El nombre «{name}» ya está en uso en esta red")
        if c.execute("SELECT COUNT(*) FROM dns_records WHERE tenant_id = ?", (tid,)).fetchone()[0] >= 200:
            raise HTTPException(409, "Máximo 200 registros por cliente")
        c.execute("INSERT INTO dns_records (tenant_id, name, ip, created_at) VALUES (?, ?, ?, ?)",
                  (tid, name, ip, int(time.time())))
        c.commit()
        dns.reload_policies()
        return zone_json(c, tid)

    @app.delete("/api/dns-zone/records/{record_id}")
    def delete_record(record_id: int, p: User, c: Conn):
        row = c.execute("SELECT * FROM dns_records WHERE id = ?", (record_id,)).fetchone()
        if not row or (not p.is_admin and row["tenant_id"] != p.id):
            raise HTTPException(404, "Registro no encontrado")
        c.execute("DELETE FROM dns_records WHERE id = ?", (record_id,))
        c.commit()
        dns.reload_policies()
        return zone_json(c, row["tenant_id"])

    @app.put("/api/dns-zone/upstreams")
    def put_upstreams(body: UpstreamsIn, p: User, c: Conn, tenant_id: int | None = None):
        tid = filters_tenant(p, tenant_id)
        t = tenant_or_404(c, tid)
        net = wg.tenant_network(settings, t["net_index"])
        clean: list[str] = []
        for raw in body.upstreams:
            try:
                ip = ipaddress.IPv4Address(raw.strip())
            except ValueError:
                raise HTTPException(422, f"IP no válida: {raw!r}") from None
            # Sólo DNS públicos o un servidor de la propia red del cliente: el
            # servidor nunca consulta en nombre de un cliente la red de otro.
            if not (ip.is_global or ip in net):
                raise HTTPException(422, f"{ip} no está permitido: usa un DNS público o uno de tu red ({net})")
            if str(ip) not in clean:
                clean.append(str(ip))
        c.execute("UPDATE tenants SET dns_upstream = ? WHERE id = ?", (" ".join(clean), tid))
        c.commit()
        dns.reload_policies()
        return zone_json(c, tid)

    @app.get("/api/admin/dns-settings")
    def get_dns_settings(_: Admin, c: Conn):
        return {"suffixes": dnsfilter.parse_suffixes(get_setting(c, "dns_suffixes")),
                "server": str(settings.server_address.ip), "upstreams": settings.dns_upstreams}

    @app.put("/api/admin/dns-settings")
    def put_dns_settings(body: SuffixesIn, admin_: Admin, c: Conn):
        clean: list[str] = []
        for raw in body.suffixes:
            suffix = _dns_name(raw, "Sufijo")
            if suffix.endswith("in-addr.arpa"):
                raise HTTPException(422, "Sufijo reservado")
            if suffix not in clean:
                clean.append(suffix)
        set_setting(c, "dns_suffixes", " ".join(clean))
        c.commit()
        dns.reload_policies()
        return get_dns_settings(admin_, c)

    # ------------------------------------------------------------------ dominios
    @app.get("/internal/tls-ask", include_in_schema=False)
    async def tls_ask(request: Request, domain: str = ""):
        # Caddy pregunta antes de pedir un certificado (on-demand TLS).
        if not local_direct(request):
            raise HTTPException(404)
        ok = await asyncio.to_thread(doms.allow_certificate, domain)
        if not ok:
            raise HTTPException(404, "Dominio no autorizado")
        return {"ok": True}

    def branding_for(c: sqlite3.Connection, request: Request) -> dict:
        owner = doms.tenant_for_host(c, domains.host_of(request.headers.get("host")))
        if owner is not None:
            return {"title": owner["name"], "tenant": True}
        return {"title": "WireGuard Cloud", "tenant": False}

    @app.get("/api/branding")
    def branding(request: Request, c: Conn):
        return branding_for(c, request)

    @app.get("/api/admin/settings")
    def get_settings(_: Admin, c: Conn):
        return {
            "main_domain": doms.main_domain(c), "force_https": doms.force_https(c),
            "server_ips": sorted(doms.expected_ips()),
            "tenant_domains": [
                {"tenant_id": r["id"], "name": r["name"], "domain": r["domain"], "enabled": bool(r["enabled"])}
                for r in c.execute("SELECT id, name, domain, enabled FROM tenants WHERE domain IS NOT NULL ORDER BY name")
            ],
        }

    @app.put("/api/admin/settings")
    def put_settings(body: SettingsIn, request: Request, _: Admin, c: Conn):
        host = _clean_host(body.main_domain)
        if host and doms.taken(c, host) and host != doms.main_domain(c):
            raise HTTPException(409, "Ese dominio ya lo usa un cliente")
        if body.force_https:
            if not host:
                raise HTTPException(409, "Para forzar HTTPS hace falta un dominio")
            # Evita dejar el panel inaccesible: el HTTPS debe funcionar antes de forzarlo.
            if request.url.scheme != "https" and not doms.https_status(host)["ok"]:
                raise HTTPException(409, f"HTTPS todavía no funciona en {host}; compruébalo antes de forzarlo")
        doms.set_main(c, host, body.force_https)
        return get_settings(_, c)

    def domain_tenant(p: Principal, tenant_id: int | None) -> int:
        if p.is_admin:
            if tenant_id is None:
                raise HTTPException(400, "tenant_id es obligatorio")
            return tenant_id
        return p.id

    @app.get("/api/domain-status")
    async def domain_status(p: User, c: Conn, target: str = "tenant", tenant_id: int | None = None):
        """Comprobación de DNS y HTTPS (sólo de dominios dados de alta, nunca arbitrarios)."""
        if target == "main":
            if not p.is_admin:
                raise HTTPException(403, "Sólo administradores")
            host = doms.main_domain(c)
        else:
            host = tenant_or_404(c, domain_tenant(p, tenant_id))["domain"]
        return await asyncio.to_thread(doms.status, host)

    @app.get("/api/tenant-domain")
    def get_tenant_domain(p: User, c: Conn, tenant_id: int | None = None):
        t = tenant_or_404(c, domain_tenant(p, tenant_id))
        return {"tenant_id": t["id"], "domain": t["domain"], "server_ips": sorted(doms.expected_ips())}

    @app.put("/api/tenant-domain")
    def put_tenant_domain(body: DomainIn, p: User, c: Conn, tenant_id: int | None = None):
        tid = domain_tenant(p, tenant_id)
        tenant_or_404(c, tid)
        host = _clean_host(body.domain)
        if host and doms.taken(c, host, exclude_tenant=tid):
            raise HTTPException(409, "Ese dominio ya está en uso")
        c.execute("UPDATE tenants SET domain = ? WHERE id = ?", (host, tid))
        return get_tenant_domain(p, c, tid)

    # ------------------------------------------------------------------ módulos
    deps = SimpleNamespace(
        settings=settings, db=database, wgm=wgm, dns=dns, doms=doms,
        Conn=Conn, User=User, Admin=Admin, Anyone=Anyone, visible_devices=visible_devices,
        tenant_or_404=tenant_or_404, apply_wg=apply_wg, scope_tenant=services_tenant,
        clean_target=clean_target, probe=_probe,
        endpoint_host=lambda c: wg.endpoint_host(c, settings),
        tenant_networks=lambda c, tid: [str(wg.tenant_network(settings, tenant_or_404(c, tid)["net_index"]))]
        + wg.tenant_lans(c, tid),
    )
    forwards.register(app, deps)
    history.register(app, deps)
    deps.notifier = notifier
    alerts.register(app, deps)
    vars(deps).update(set_session=set_session, limiter=limiter, device_for=device_for, render_config=render_config)
    members.register(app, deps)

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
    def manifest(request: Request, c: Conn):
        data = json.loads((STATIC_DIR / "manifest.webmanifest").read_text())
        brand = branding_for(c, request)
        if brand["tenant"]:
            data["name"] = brand["title"]
            data["short_name"] = brand["title"][:12]
        return JSONResponse(data, media_type="application/manifest+json", headers={"Cache-Control": "no-cache"})

    return app

"""Subdominios de clientes en Cloudflare (Ajustes › Subdominios de clientes).

Con un token de la API de Cloudflare (permiso «Zone › DNS › Edit») y un dominio
de esa cuenta (p. ej. wgcloud.app), cada cliente tiene su dirección:

  acme.wgcloud.app     A -> IP del servidor (puertos abiertos: acme.wgcloud.app:3389)
  *.acme.wgcloud.app   A -> IP del servidor (servicios HTTPS: nas.acme.wgcloud.app)

Los registros son «solo DNS» (nube gris): un puerto TCP/UDP no pasa por el
proxy de Cloudflare. El panel sólo toca los registros que crea él (llevan el
comentario «wgp: …»); si ya existe otro registro con ese nombre, no lo pisa y lo
indica. Un bucle compara cada minuto lo que debería haber con lo último aplicado
y cada 30 min revisa también lo que hay en Cloudflare (por si se borró a mano).

Sin `from __future__ import annotations`: FastAPI evalúa las dependencias de `deps`.
"""
import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field

from .db import Database, get_setting, set_setting

log = logging.getLogger("wgp.cloudflare")

API = os.environ.get("CLOUDFLARE_API", "https://api.cloudflare.com/client/v4")
TAG = "wgp:"
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
RESERVED = {"www", "mail", "smtp", "imap", "pop", "ftp", "ns1", "ns2", "api", "admin", "panel", "vpn", "app", "dashboard", "status"}
FULL_EVERY = 1800


class CloudflareError(Exception):
    pass


def dns_label(username: str) -> str:
    label = re.sub(r"[^a-z0-9-]+", "-", (username or "").lower()).strip("-")[:63].strip("-")
    return label or "cliente"


def zone_of(c: sqlite3.Connection) -> Optional[str]:
    """Dominio de Cloudflare si los subdominios de clientes están activos."""
    if get_setting(c, "cf_enabled") == "1" and get_setting(c, "cf_token") and get_setting(c, "cf_zone_id"):
        return get_setting(c, "cf_zone") or None
    return None


def taken_labels(c: sqlite3.Connection, zone: Optional[str]) -> set:
    """Etiquetas que ya usan el panel o la página pública dentro del dominio (no pueden ser de un cliente)."""
    out = set(RESERVED)
    if zone:
        hosts = [get_setting(c, "main_domain") or ""] + (get_setting(c, "site_domains") or "").split()
        out |= {h[: -len(zone) - 1].split(".")[-1] for h in hosts if h.endswith("." + zone)}
    return out


def assign(c: sqlite3.Connection) -> None:
    """Subdominio estable para los clientes que aún no lo tienen (a partir del usuario)."""
    blocked = taken_labels(c, get_setting(c, "cf_zone"))
    for t in c.execute("SELECT id, username FROM tenants WHERE subdomain IS NULL ORDER BY id").fetchall():
        label = dns_label(t["username"])
        if label in blocked or c.execute("SELECT 1 FROM tenants WHERE subdomain = ?", (label,)).fetchone():
            label = f"{label[:55]}-{t['id']}"
        c.execute("UPDATE tenants SET subdomain = ? WHERE id = ?", (label, t["id"]))


def tenant_by_host(c: sqlite3.Connection, host: str) -> Optional[sqlite3.Row]:
    """acme.<dominio> -> el cliente acme (su dirección por defecto)."""
    zone = zone_of(c)
    if not zone or not host or not host.endswith("." + zone):
        return None
    label = host[: -len(zone) - 1]
    if "." in label:
        return None
    return c.execute("SELECT * FROM tenants WHERE subdomain = ?", (label,)).fetchone()


def proxy_default(c: sqlite3.Connection) -> bool:
    return get_setting(c, "cf_proxy_default") == "1"


def tenant_proxied(c: sqlite3.Connection, t: sqlite3.Row) -> bool:
    value = t["cf_proxied"]
    return proxy_default(c) if value is None else bool(value)


def proxy_hosts(c: sqlite3.Connection) -> dict:
    """Nube naranja elegida para dominios que no crea el panel (el del panel, la página pública)."""
    return json.loads(get_setting(c, "cf_proxy_hosts") or "{}")


def is_proxied(c: sqlite3.Connection, host: str) -> bool:
    """¿Pasa por el proxy de Cloudflare? (entonces su DNS apunta a Cloudflare, no a este servidor)."""
    zone = zone_of(c)
    if not zone or not host or not (host == zone or host.endswith("." + zone)):
        return False
    if host in proxy_hosts(c):
        return bool(proxy_hosts(c)[host])
    parts = host[: -len(zone) - 1].split(".") if host != zone else []
    if parts:
        t = c.execute("SELECT * FROM tenants WHERE subdomain = ?", (parts[-1],)).fetchone()
        if t is not None and (len(parts) == 1 or get_setting(c, "cf_wildcard") != "0"):
            return tenant_proxied(c, t)
    return False


class CloudflareDNS:
    def __init__(self, db: Database, doms):
        self.db = db
        self.doms = doms
        self._task: Optional[asyncio.Task] = None
        self._applied: Optional[str] = None
        self._full_at = 0.0

    # ---- configuración
    def config(self, c: sqlite3.Connection) -> dict:
        return {
            "enabled": get_setting(c, "cf_enabled") == "1",
            "zone": get_setting(c, "cf_zone") or "",
            "zone_id": get_setting(c, "cf_zone_id") or "",
            "token": get_setting(c, "cf_token") or "",
            "account": get_setting(c, "cf_account") or "",
            "wildcard": get_setting(c, "cf_wildcard") != "0",
        }

    def active(self, c: sqlite3.Connection) -> bool:
        cfg = self.config(c)
        return cfg["enabled"] and bool(cfg["token"] and cfg["zone_id"])

    def host_for(self, c: sqlite3.Connection, tenant: sqlite3.Row) -> Optional[str]:
        """acme.wgcloud.app si los subdominios están activos (si no, None)."""
        if not tenant["subdomain"] or not self.active(c):
            return None
        return f"{tenant['subdomain']}.{self.config(c)['zone']}"

    def server_ip(self) -> Optional[str]:
        for ip in sorted(self.doms.expected_ips()):
            if ipaddress.ip_address(ip).version == 4:
                return ip
        return None

    # ---- API de Cloudflare
    def call(self, token: str, method: str, path: str, body: Optional[dict] = None, query: Optional[dict] = None) -> dict:
        url = f"{API}{path}" + (f"?{urllib.parse.urlencode(query)}" if query else "")
        req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:   # noqa: S310 - API fija
                data = json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                data = json.loads(exc.read() or b"{}")
            except ValueError:
                data = {}
            errors = "; ".join(e.get("message", "") for e in data.get("errors", [])) or f"HTTP {exc.code}"
            raise CloudflareError(errors) from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise CloudflareError(f"No se pudo conectar con Cloudflare ({exc})") from None
        if not data.get("success", False):
            raise CloudflareError("; ".join(e.get("message", "") for e in data.get("errors", [])) or "Respuesta no válida")
        return data

    def zones(self, token: str, account: str = "") -> list[dict]:
        """Dominios que ve el token. Los tokens de cuenta (Gestionar cuenta › Tokens de API) se
        validan en /accounts/<id>/tokens/verify; los de usuario, en /user/tokens/verify."""
        try:
            self.call(token, "GET", f"/accounts/{account}/tokens/verify" if account else "/user/tokens/verify")
        except CloudflareError as exc:
            if account:
                raise
            raise CloudflareError(f"{exc}. Si es un token de cuenta, indica también el ID de cuenta") from None
        query = {"per_page": 50, "status": "active", **({"account.id": account} if account else {})}
        data = self.call(token, "GET", "/zones", query=query)
        return [{"id": z["id"], "name": z["name"], "account": (z.get("account") or {}).get("id", "")} for z in data.get("result", [])]

    def records(self, token: str, zone_id: str, **query) -> list[dict]:
        out, page = [], 1
        while True:
            data = self.call(token, "GET", f"/zones/{zone_id}/dns_records", query={"per_page": 500, "page": page, **query})
            out += data.get("result", [])
            info = data.get("result_info") or {}
            if page >= (info.get("total_pages") or 1):
                return out
            page += 1

    # ---- sincronización
    def desired(self, c: sqlite3.Connection) -> dict:
        cfg = self.config(c)
        ip = self.server_ip()
        if not ip:
            raise CloudflareError("No se conoce la IPv4 pública del servidor (WG_ENDPOINT)")
        out = {}
        for t in c.execute("SELECT * FROM tenants WHERE subdomain IS NOT NULL ORDER BY id").fetchall():
            host = f"{t['subdomain']}.{cfg['zone']}"
            proxied = tenant_proxied(c, t)
            out[host] = (ip, f"{TAG} cliente {t['username']}", proxied)
            if cfg["wildcard"]:
                out[f"*.{host}"] = (ip, f"{TAG} servicios de {t['username']}", proxied)
        return out

    def external(self, c: sqlite3.Connection) -> dict:
        """Nube naranja de dominios que no crea el panel (sólo los que el admin ha tocado)."""
        zone = zone_of(c)
        if not zone:
            return {}
        return {h: bool(v) for h, v in proxy_hosts(c).items() if h == zone or h.endswith("." + zone)}

    def sync(self, force: bool = False) -> dict:
        with self.db.conn() as c:
            assign(c)
            cfg = self.config(c)
            want = self.desired(c) if self.active(c) else {}
            extra = self.external(c) if self.active(c) else {}
        if not cfg["token"] or not cfg["zone_id"]:
            return self._record(ok=True, error=None, count=0)
        digest = hashlib.sha256(json.dumps([sorted(want.items()), sorted(extra.items())]).encode()).hexdigest()
        if not force and digest == self._applied and time.monotonic() - self._full_at < FULL_EVERY:
            return self.state()
        token, zone = cfg["token"], cfg["zone_id"]
        conflicts, changes = [], 0
        try:
            ours = {r["name"]: r for r in self.records(token, zone, **{"comment.startswith": TAG})
                    if (r.get("comment") or "").startswith(TAG)}
            for name, (ip, comment, proxied) in want.items():
                cur = ours.pop(name, None)
                # Con proxy el TTL lo fija Cloudflare (1 = automático).
                body = {"type": "A", "name": name, "content": ip, "ttl": 1 if proxied else 300, "proxied": proxied, "comment": comment}
                if cur is None:
                    if self.records(token, zone, name=name):
                        conflicts.append(name)   # ya existe un registro que no es nuestro: no se toca
                        continue
                    self.call(token, "POST", f"/zones/{zone}/dns_records", body)
                    changes += 1
                elif cur.get("content") != ip or cur.get("type") != "A" or bool(cur.get("proxied")) != proxied:
                    self.call(token, "PUT", f"/zones/{zone}/dns_records/{cur['id']}", body)
                    changes += 1
            for r in ours.values():   # clientes borrados, subdominio cambiado o desactivado
                self.call(token, "DELETE", f"/zones/{zone}/dns_records/{r['id']}")
                changes += 1
            for name, proxied in extra.items():   # dominio del panel / página pública: sólo la nube
                for r in self.records(token, zone, name=name):
                    if r.get("type") in ("A", "AAAA", "CNAME") and bool(r.get("proxied")) != proxied:
                        self.call(token, "PATCH", f"/zones/{zone}/dns_records/{r['id']}", {"proxied": proxied})
                        changes += 1
        except CloudflareError as exc:
            log.warning("Sincronización con Cloudflare: %s", exc)
            return self._record(ok=False, error=str(exc), count=len(want))
        self._applied, self._full_at = digest, time.monotonic()
        if changes:
            log.info("Cloudflare: %d cambios en %s", changes, cfg["zone"])
        error = f"Ya existen registros que no son del panel: {', '.join(sorted(conflicts)[:5])}" if conflicts else None
        return self._record(ok=not conflicts, error=error, count=len(want) - len(conflicts))

    def _record(self, ok: bool, error: Optional[str], count: int) -> dict:
        with self.db.conn() as c:
            set_setting(c, "cf_state", json.dumps({"at": int(time.time()), "ok": ok, "error": error, "records": count}))
        return self.state()

    def state(self) -> dict:
        with self.db.conn() as c:
            return json.loads(get_setting(c, "cf_state") or "null") or {"at": None, "ok": None, "error": None, "records": 0}

    def reset(self) -> None:
        self._applied = None

    async def run(self) -> None:
        while True:
            await asyncio.sleep(60)
            try:
                with self.db.conn() as c:
                    configured = bool(self.config(c)["token"])
                if configured:
                    await asyncio.to_thread(self.sync)
            except Exception:  # noqa: BLE001 - el bucle no debe morir
                log.exception("Error al sincronizar con Cloudflare")

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.ensure_future(self.run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()


ACCOUNT_RE = re.compile(r"^[0-9a-f]{32}$")


def clean_account(value: Optional[str]) -> Optional[str]:
    """None = no cambiar; "" = sin cuenta; si no, el ID de 32 caracteres hexadecimales."""
    if value is None:
        return None
    value = value.strip().lower()
    if value and not ACCOUNT_RE.match(value):
        raise HTTPException(422, "ID de cuenta no válido: 32 caracteres hexadecimales (Cloudflare › tu cuenta › Resumen › ID de cuenta)")
    return value


class CloudflareIn(BaseModel):
    proxy_default: Optional[bool] = None
    token: Optional[str] = Field(default=None, max_length=200)
    account: Optional[str] = Field(default=None, max_length=64)
    zone: Optional[str] = Field(default=None, max_length=253)
    enabled: Optional[bool] = None
    wildcard: Optional[bool] = None


class TokenIn(BaseModel):
    token: Optional[str] = Field(default=None, max_length=200)
    account: Optional[str] = Field(default=None, max_length=64)


class ProxyIn(BaseModel):
    proxied: Optional[bool] = None   # None = el valor por defecto


class HostProxyIn(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    proxied: bool


class SubdomainIn(BaseModel):
    subdomain: str = Field(min_length=1, max_length=63)


def register(app, d) -> None:
    cf: CloudflareDNS = d.cloudflare

    def view(c: sqlite3.Connection) -> dict:
        cfg = cf.config(c)
        first = c.execute("SELECT subdomain FROM tenants WHERE subdomain IS NOT NULL ORDER BY id LIMIT 1").fetchone()
        return {"enabled": cfg["enabled"], "zone": cfg["zone"], "has_token": bool(cfg["token"]), "wildcard": cfg["wildcard"],
                "account": cfg["account"], "proxy_default": proxy_default(c),
                "proxy_hosts": d.cf_candidates(c) if hasattr(d, "cf_candidates") else [],
                "ip": cf.server_ip(), "state": cf.state(),
                "example": f"{first['subdomain'] if first else 'acme'}.{cfg['zone'] or 'tudominio.com'}"}

    @app.get("/api/admin/cloudflare")
    def get_cf(_: d.Admin, c: d.Conn):
        return view(c)

    @app.post("/api/admin/cloudflare/zones")
    async def cf_zones(body: TokenIn, _: d.Admin, c: d.Conn):
        token = (body.token or "").strip() or cf.config(c)["token"]
        account = clean_account(body.account)
        if not token:
            raise HTTPException(422, "Pega el token de la API de Cloudflare")
        try:
            return {"zones": await asyncio.to_thread(cf.zones, token, cf.config(c)["account"] if account is None else account)}
        except CloudflareError as exc:
            raise HTTPException(400, f"Cloudflare: {exc}")

    @app.put("/api/admin/cloudflare")
    async def put_cf(body: CloudflareIn, _: d.Admin, c: d.Conn):
        cfg = cf.config(c)
        token = (body.token or "").strip() or cfg["token"]
        account = clean_account(body.account)
        if account is None:
            account = cfg["account"]
        if body.zone is not None or body.token or body.account is not None:
            zone = d.normalize_host(body.zone if body.zone is not None else cfg["zone"])
            if not token or not zone:
                raise HTTPException(422, "Indica el token y el dominio")
            try:
                zones = await asyncio.to_thread(cf.zones, token, account)
            except CloudflareError as exc:
                raise HTTPException(400, f"Cloudflare: {exc}")
            match = next((z for z in zones if z["name"] == zone), None)
            if not match:
                raise HTTPException(422, f"El token no tiene acceso a {zone}: en Cloudflare, dale permiso «Zona › DNS › Editar» sobre ese dominio")
            if cfg["zone_id"] and cfg["zone_id"] != match["id"] and cfg["enabled"]:
                # Cambio de dominio: primero se borran los registros del anterior.
                set_setting(c, "cf_enabled", "0")
                c.commit()
                cf.reset()
                await asyncio.to_thread(cf.sync, True)
                set_setting(c, "cf_enabled", "1")
            set_setting(c, "cf_token", token)
            set_setting(c, "cf_zone", zone)
            set_setting(c, "cf_zone_id", match["id"])
            set_setting(c, "cf_account", account or match.get("account", ""))
        if body.wildcard is not None:
            set_setting(c, "cf_wildcard", "1" if body.wildcard else "0")
        if body.proxy_default is not None:
            set_setting(c, "cf_proxy_default", "1" if body.proxy_default else "0")
        if body.enabled is not None:
            if body.enabled and not (get_setting(c, "cf_token") and get_setting(c, "cf_zone_id")):
                raise HTTPException(422, "Configura primero el token y el dominio")
            set_setting(c, "cf_enabled", "1" if body.enabled else "0")
        c.commit()
        cf.reset()
        await asyncio.to_thread(cf.sync, True)
        return view(c)

    @app.post("/api/admin/cloudflare/sync")
    async def sync_cf(_: d.Admin, c: d.Conn):
        cf.reset()
        await asyncio.to_thread(cf.sync, True)
        return view(c)

    @app.delete("/api/admin/cloudflare")
    async def delete_cf(_: d.Admin, c: d.Conn):
        """Desconecta Cloudflare: borra los registros creados por el panel y olvida el token."""
        set_setting(c, "cf_enabled", "0")
        c.commit()
        cf.reset()
        state = await asyncio.to_thread(cf.sync, True)
        if state.get("ok") is False:
            raise HTTPException(400, f"No se pudieron borrar los registros: {state.get('error')}")
        for key in ("cf_token", "cf_zone", "cf_zone_id", "cf_account", "cf_state", "cf_proxy_hosts"):
            c.execute("DELETE FROM settings WHERE key = ?", (key,))
        return view(c)

    async def change_subdomain(c: sqlite3.Connection, tenant_id: int, raw: str) -> dict:
        d.tenant_or_404(c, tenant_id)
        label = raw.strip().lower()
        if not LABEL_RE.match(label) or label in taken_labels(c, cf.config(c)["zone"]):
            raise HTTPException(422, "Subdominio no válido: minúsculas, números y guiones")
        other = c.execute("SELECT id FROM tenants WHERE subdomain = ? AND id != ?", (label, tenant_id)).fetchone()
        zone = cf.config(c)["zone"]
        if other or (zone and d.doms.taken(c, f"{label}.{zone}", exclude_tenant=tenant_id)):
            raise HTTPException(409, "Ese subdominio ya está en uso")
        c.execute("UPDATE tenants SET subdomain = ? WHERE id = ?", (label, tenant_id))
        c.commit()
        await asyncio.to_thread(cf.sync, True)
        return {"subdomain": label, "host": cf.host_for(c, d.tenant_or_404(c, tenant_id))}

    @app.put("/api/admin/tenants/{tenant_id}/subdomain")
    async def put_subdomain(tenant_id: int, body: SubdomainIn, _: d.Admin, c: d.Conn):
        return await change_subdomain(c, tenant_id, body.subdomain)

    @app.put("/api/me/subdomain")
    async def put_my_subdomain(body: SubdomainIn, p: d.User, c: d.Conn):
        """El cliente cambia su dirección por defecto (acme.<dominio>)."""
        if p.is_admin:
            raise HTTPException(400, "Sólo para clientes")
        if not cf.active(c):
            raise HTTPException(409, "Las direcciones de cliente no están activas")
        return await change_subdomain(c, p.id, body.subdomain)

    # ---------------------------------------------------------------- nube naranja (proxy de Cloudflare)
    def endpoint_host(c: sqlite3.Connection) -> str:
        return (d.endpoint_host(c) or "").lower()

    @app.put("/api/admin/tenants/{tenant_id}/proxy")
    async def put_tenant_proxy(tenant_id: int, body: ProxyIn, _: d.Admin, c: d.Conn):
        t = d.tenant_or_404(c, tenant_id)
        if body.proxied and cf.host_for(c, t) == endpoint_host(c):
            raise HTTPException(409, "Ese nombre es el endpoint de WireGuard (UDP): no puede ir por el proxy")
        c.execute("UPDATE tenants SET cf_proxied = ? WHERE id = ?", (None if body.proxied is None else int(body.proxied), tenant_id))
        c.commit()
        cf.reset()
        await asyncio.to_thread(cf.sync, True)
        t = d.tenant_or_404(c, tenant_id)
        return {"proxied": tenant_proxied(c, t), "custom": t["cf_proxied"] is not None, "state": cf.state()}

    @app.put("/api/admin/cloudflare/proxy")
    async def put_host_proxy(body: HostProxyIn, _: d.Admin, c: d.Conn):
        host = d.normalize_host(body.host) or ""
        if host not in {x["host"] for x in candidates(c)}:
            raise HTTPException(422, "Ese dominio no es del panel ni de la página pública en tu dominio de Cloudflare")
        if body.proxied and host == endpoint_host(c):
            raise HTTPException(409, "Ese nombre es el endpoint de WireGuard (UDP): no puede ir por el proxy. "
                                     "Usa otro nombre para el endpoint en Ajustes › Endpoint de WireGuard.")
        hosts = proxy_hosts(c)
        hosts[host] = bool(body.proxied)
        set_setting(c, "cf_proxy_hosts", json.dumps(hosts))
        c.commit()
        cf.reset()
        await asyncio.to_thread(cf.sync, True)
        return view(c)

    def candidates(c: sqlite3.Connection) -> list[dict]:
        """Dominios del panel y de la página pública que están en el dominio de Cloudflare."""
        zone = cf.config(c)["zone"]
        if not zone:
            return []
        found = [("panel", d.doms.main_domain(c))] + [("site", h) for h in d.doms.site_domains(c)]
        hosts = proxy_hosts(c)
        return [{"host": h, "kind": k, "proxied": bool(hosts.get(h, False)), "known": h in hosts, "endpoint": h == endpoint_host(c)}
                for k, h in found if h and (h == zone or h.endswith("." + zone))]

    d.cf_candidates = candidates

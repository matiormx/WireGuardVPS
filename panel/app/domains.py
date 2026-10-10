"""Dominios personalizados con HTTPS automático.

Caddy (proxy HTTPS en el host) funciona en modo «on-demand TLS»: la primera vez
que alguien visita un dominio, antes de pedir el certificado a Let's Encrypt,
pregunta a /internal/tls-ask si ese dominio está autorizado. Así el admin y los
clientes añaden o quitan dominios desde el panel sin tocar el servidor:

  * dominio principal  (Ajustes del admin)      -> panel completo
  * dominio de cliente (Cuenta / ficha cliente) -> panel con la marca del cliente;
                                                    sólo ese cliente puede entrar

Sólo se autoriza un dominio dado de alta cuyo DNS apunte a este servidor, de
modo que nadie puede provocar certificados para dominios ajenos.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import sqlite3
import ssl
import time
import urllib.error
import urllib.request

from . import cfdns
from .config import Settings
from .db import Database, get_setting, set_setting

HOST_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")


def normalize_host(value: str | None) -> str | None:
    """Valida un nombre de dominio (sin esquema, puerto ni ruta). None si no es válido."""
    if not value:
        return None
    host = value.strip().lower()
    for prefix in ("https://", "http://"):
        host = host.removeprefix(prefix)
    host = host.split("/", 1)[0].rstrip(".")
    try:
        ipaddress.ip_address(host)
        return None  # una IP no es un dominio
    except ValueError:
        pass
    return host if HOST_RE.match(host) else None


def host_of(header: str | None) -> str:
    """Cabecera Host -> nombre sin puerto, en minúsculas."""
    host = (header or "").strip().lower()
    if host.startswith("["):
        return host.split("]", 1)[0] + "]"
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


class Domains:
    def __init__(self, settings: Settings, database: Database) -> None:
        self.settings = settings
        self.db = database
        self._expected: tuple[float, set[str]] = (0.0, set())

    # ------------------------------------------------------------------ datos
    def main_domain(self, c: sqlite3.Connection) -> str | None:
        return get_setting(c, "main_domain") or None

    @staticmethod
    def site_domains(c: sqlite3.Connection, only_enabled: bool = False) -> list[str]:
        """Dominios de la página pública (presentación del servicio y planes)."""
        if only_enabled and get_setting(c, "site_enabled") != "1":
            return []
        return (get_setting(c, "site_domains") or "").split()

    def force_https(self, c: sqlite3.Connection) -> bool:
        return get_setting(c, "force_https") == "1" and bool(self.main_domain(c))

    def set_main(self, c: sqlite3.Connection, domain: str | None, force: bool) -> None:
        set_setting(c, "main_domain", domain or "")
        set_setting(c, "force_https", "1" if (force and domain) else "0")

    def tenant_for_host(self, c: sqlite3.Connection, host: str) -> sqlite3.Row | None:
        """El cliente de un dominio: su dominio propio o su dirección por defecto (acme.<dominio de Cloudflare>)."""
        if not host:
            return None
        row = c.execute("SELECT * FROM tenants WHERE domain = ?", (host,)).fetchone()
        return row if row is not None else cfdns.tenant_by_host(c, host)

    def taken(self, c: sqlite3.Connection, host: str, exclude_tenant: int | None = None,
              exclude_service: int | None = None) -> bool:
        """Un nombre sólo puede ser el del panel, el de un cliente o el de un servicio publicado."""
        if host == self.main_domain(c) or host in self.site_domains(c):
            return True
        svc = c.execute("SELECT id FROM services WHERE hostname = ?", (host,)).fetchone()
        if svc and svc["id"] != exclude_service:
            return True
        row = c.execute("SELECT id FROM tenants WHERE domain = ?", (host,)).fetchone() or cfdns.tenant_by_host(c, host)
        return bool(row) and row["id"] != exclude_tenant

    def registered(self, c: sqlite3.Connection, host: str) -> bool:
        if host and (host == self.main_domain(c) or host in self.site_domains(c, only_enabled=True)):
            return True
        row = self.tenant_for_host(c, host)
        if row is not None:
            return bool(row["enabled"])
        svc = c.execute("""SELECT 1 FROM services s JOIN tenants t ON t.id = s.tenant_id
                           WHERE s.hostname = ? AND s.enabled = 1 AND t.enabled = 1""", (host,)).fetchone()
        return svc is not None

    def seed_from_env(self, domain: str | None) -> None:
        """PANEL_DOMAIN (instalaciones anteriores): se usa si aún no hay dominio en el panel."""
        host = normalize_host(domain)
        if not host:
            return
        with self.db.conn() as c:
            if not self.main_domain(c) and not self.taken(c, host):
                self.set_main(c, host, True)

    # ------------------------------------------------------------------ comprobaciones
    @staticmethod
    def resolve(host: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
        except OSError:
            return []
        return sorted({i[4][0] for i in infos})

    def expected_ips(self) -> set[str]:
        """IP(s) públicas del servidor (WG_ENDPOINT: IP o nombre)."""
        ts, ips = self._expected
        if time.monotonic() - ts < 300 and ips:
            return ips
        endpoint = self.settings.endpoint
        try:
            ips = {str(ipaddress.ip_address(endpoint))}
        except ValueError:
            ips = set(self.resolve(endpoint))
        self._expected = (time.monotonic(), ips)
        return ips

    def dns_status(self, host: str) -> dict:
        resolved = self.resolve(host)
        expected = sorted(self.expected_ips())
        ok = bool(resolved) and (not expected or bool(set(resolved) & set(expected)))
        with self.db.conn() as c:
            proxied = cfdns.is_proxied(c, host)
        # Con la nube naranja el DNS devuelve IPs de Cloudflare: es lo esperado.
        return {"ok": ok or (proxied and bool(resolved)), "resolved": resolved, "expected": expected, "proxied": proxied}

    @staticmethod
    def https_status(host: str, any_status: bool = False) -> dict:
        """Comprueba el certificado. any_status: cualquier respuesta HTTP vale (servicios
        publicados, donde el equipo de destino puede pedir contraseña o no tener /healthz)."""
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(f"https://{host}/healthz", headers={"User-Agent": "wgp-panel/domain-check"})
            # Conexión directa (sin proxies del entorno): se comprueba este mismo servidor.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
            with opener.open(req, timeout=12) as res:
                return {"ok": res.status == 200, "error": None}
        except urllib.error.HTTPError as exc:
            return {"ok": any_status, "error": None if any_status else f"HTTP {exc.code}"}
        except ssl.SSLError as exc:
            return {"ok": False, "error": f"Certificado aún no disponible ({exc.reason or exc})"}
        except urllib.error.URLError as exc:
            return {"ok": False, "error": str(exc.reason)}
        except (OSError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}

    def status(self, host: str | None, any_status: bool = False) -> dict:
        if not host:
            return {"domain": None, "dns": None, "https": None, "server_ips": sorted(self.expected_ips())}
        dns = self.dns_status(host)
        # Sólo se prueba HTTPS si el DNS apunta aquí: la petición va a nuestro propio
        # servidor y, de paso, hace que Caddy solicite el certificado.
        https = self.https_status(host, any_status) if dns["ok"] else {"ok": False, "error": "El DNS aún no apunta a este servidor"}
        return {"domain": host, "dns": dns, "https": https, "server_ips": dns["expected"]}

    def allow_certificate(self, host: str) -> bool:
        """Respuesta a Caddy (on-demand TLS): ¿se puede emitir certificado para host?"""
        host = normalize_host(host) or ""
        with self.db.conn() as c:
            if not self.registered(c, host):
                return False
        return self.dns_status(host)["ok"]

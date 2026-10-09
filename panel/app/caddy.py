"""Servicios publicados: configuración de Caddy generada por el panel.

Cada cliente puede publicar servicios de su red (NAS, cámaras, Home Assistant…)
en un nombre propio con HTTPS, p. ej. nas.suempresa.com -> 10.252.1.50:5000.

El panel genera el Caddyfile completo (servicios + el propio panel) y lo envía
a la API de administración de Caddy (sólo escucha en localhost). Caddy aplica
el cambio sin cortar conexiones, y con `--resume` conserva la última
configuración aunque se reinicie. Todos los valores que se escriben en el
Caddyfile están validados antes (nombres, IPs, puertos, usuarios y hashes).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import threading
import urllib.error
import urllib.request

from .config import Settings
from .db import Database

log = logging.getLogger("wgp.caddy")

USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
BCRYPT_RE = re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")


def render_caddyfile(panel_port: int, acme_email: str, services: list, local_certs: bool = False) -> str:
    lines = ["{"]
    if local_certs:
        lines.append("\tlocal_certs  # desarrollo/pruebas: CA interna de Caddy en lugar de Let's Encrypt")
    if acme_email:
        lines.append(f"\temail {acme_email}")
    lines += [
        "\ton_demand_tls {",
        f"\t\task http://127.0.0.1:{panel_port}/internal/tls-ask",
        "\t}",
        "}",
        "",
    ]
    for svc in services:
        block = [
            f"# servicio {svc['id']} (cliente {svc['tenant_id']})",
            f"{svc['hostname']} {{",
            "\ttls {", "\t\ton_demand", "\t}",
            "\tencode zstd gzip",
        ]
        if svc["auth_user"] or svc["auth_hash"]:
            if not USER_RE.match(svc["auth_user"]) or not BCRYPT_RE.match(svc["auth_hash"]):
                log.error("Servicio %s omitido: protección no válida", svc["id"])
                continue  # nunca debería ocurrir (validado al guardar): mejor omitir que publicar sin clave
            block += ["\tbasic_auth {", f"\t\t{svc['auth_user']} {svc['auth_hash']}", "\t}"]
        upstream = f"{svc['scheme']}://{svc['target_ip']}:{int(svc['target_port'])}"
        if svc["scheme"] == "https":
            # Los NAS y cámaras suelen usar certificados autofirmados en la red interna.
            block += [f"\treverse_proxy {upstream} {{", "\t\ttransport http {", "\t\t\ttls_insecure_skip_verify",
                      "\t\t}", "\t}"]
        else:
            block.append(f"\treverse_proxy {upstream}")
        lines += block + ["}", ""]
    lines += [
        "# Panel (dominio principal y dominios de clientes)",
        "https:// {",
        "\ttls {", "\t\ton_demand", "\t}",
        "\tencode zstd gzip",
        '\theader Strict-Transport-Security "max-age=31536000"',
        f"\treverse_proxy 127.0.0.1:{panel_port}",
        "}",
        "",
        "http:// {",
        "\tredir https://{host}{uri} 308",
        "}",
        "",
    ]
    return "\n".join(lines)


class CaddySync:
    """Mantiene Caddy alineado con los servicios publicados en la base de datos."""

    def __init__(self, settings: Settings, database: Database, admin_url: str, acme_email: str) -> None:
        self.settings = settings
        self.db = database
        self.admin_url = admin_url.rstrip("/")
        self.acme_email = acme_email
        self.last_error: str | None = None
        self.last_hash: str | None = None
        self._task: asyncio.Task | None = None
        # Un envío cada vez: la configuración se genera dentro del cerrojo, así el
        # último envío siempre lleva el estado más reciente de la base de datos.
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self.admin_url)

    def current(self) -> str:
        with self.db.conn() as c:
            rows = c.execute(
                """SELECT s.* FROM services s JOIN tenants t ON t.id = s.tenant_id
                   WHERE s.enabled = 1 AND t.enabled = 1 ORDER BY s.hostname"""
            ).fetchall()
        return render_caddyfile(self._panel_port(), self.acme_email, rows,
                                local_certs=os.environ.get("CADDY_LOCAL_CERTS", "").lower() == "true")

    @staticmethod
    def _panel_port() -> int:
        return int(os.environ.get("PANEL_PORT", "5000"))

    def push(self, force: bool = False) -> bool:
        """Envía la configuración a Caddy (Caddy ignora una configuración idéntica)."""
        if not self.enabled:
            return False
        with self._lock:
            return self._push(force)

    def _push(self, force: bool) -> bool:
        body = self.current().encode()
        digest = hashlib.sha256(body).hexdigest()
        req = urllib.request.Request(f"{self.admin_url}/load", data=body, method="POST",
                                     headers={"Content-Type": "text/caddyfile"})
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=8) as res:
                res.read()
        except urllib.error.HTTPError as exc:
            self.last_error = f"Caddy rechazó la configuración: {exc.read().decode(errors='replace')[:300]}"
            log.error(self.last_error)
            return False
        except (OSError, ValueError) as exc:
            self.last_error = f"Caddy no responde en {self.admin_url}: {exc}"
            if force:
                log.warning(self.last_error)
            return False
        if digest != self.last_hash:
            log.info("Configuración de Caddy actualizada")
        self.last_hash, self.last_error = digest, None
        return True

    async def run(self) -> None:
        # Reintenta periódicamente: cubre reinicios de Caddy y arranques en otro orden.
        while True:
            await asyncio.to_thread(self.push)
            await asyncio.sleep(60)

    def start(self) -> None:
        if self.enabled and self._task is None:
            self._task = asyncio.ensure_future(self.run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

"""Nombres reservados: palabras que no se pueden usar como usuario ni como subdominio de cliente.

Evita que un cliente se llame «admin», «www», «soporte»… (suplantación) o que su
dirección (usuario.<dominio>) choque con nombres de servicio. La lista viene con
valores razonables y el administrador la edita en Ajustes › Nombres reservados.
Las cuentas que ya existen no se tocan: sólo se comprueba al crear o renombrar.

La comparación ignora mayúsculas y separadores: «Admin», «ad_min» o «AD-MIN»
cuentan como «admin».

Sin `from __future__ import annotations`: FastAPI evalúa las dependencias de `deps`.
"""
import re
import sqlite3
from typing import List

from fastapi import HTTPException
from pydantic import BaseModel, Field

from .db import get_setting, set_setting

DEFAULT_WORDS = sorted({
    # administración y sistema
    "admin", "administrator", "administrador", "admins", "root", "superuser", "sysadmin", "system", "sistema",
    "owner", "staff", "moderator", "operator", "operador", "manager", "master", "webmaster", "hostmaster", "postmaster",
    # soporte y contacto (suplantación)
    "support", "soporte", "help", "ayuda", "helpdesk", "info", "contact", "contacto", "sales", "ventas", "billing",
    "facturacion", "pagos", "payments", "security", "seguridad", "abuse", "legal", "privacy", "privacidad",
    "noreply", "no-reply", "mailer-daemon", "notifications", "avisos",
    # servicios y DNS
    "www", "www1", "www2", "web", "mail", "email", "correo", "webmail", "smtp", "imap", "pop", "pop3", "mx", "ns",
    "ns1", "ns2", "ns3", "ns4", "dns", "ftp", "sftp", "ssh", "vpn", "wg", "wireguard", "autodiscover", "autoconfig",
    "cpanel", "whm", "calendar", "cdn", "static", "assets", "media", "files", "img", "images", "download", "downloads",
    "update", "updates", "git", "ci", "monitor", "metrics", "grafana", "prometheus", "status", "estado", "health", "healthz",
    # el panel y sus rutas
    "api", "app", "apps", "panel", "dashboard", "console", "consola", "portal", "login", "logout", "signin", "signup",
    "register", "registro", "account", "cuenta", "accounts", "auth", "oauth", "sso", "brand", "internal", "intranet",
    "invite", "reset", "settings", "ajustes",
    # genéricos y ambiguos
    "localhost", "server", "servidor", "host", "gateway", "router", "proxy", "cloud", "test", "testing", "dev",
    "staging", "prod", "demo", "beta", "null", "undefined", "anonymous", "guest", "invitado", "user", "usuario",
    "users", "usuarios", "client", "clients", "cliente", "clientes", "blog", "docs", "shop", "tienda", "store",
    "news", "forum", "chat",
})
WORD_RE = re.compile(r"^[a-z0-9-]{1,63}$")


def normalize(name: str) -> str:
    """Forma comparable: minúsculas y sin separadores (Ad_Min -> admin)."""
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def words(c: sqlite3.Connection) -> List[str]:
    raw = get_setting(c, "reserved_words")
    return DEFAULT_WORDS if raw is None else [w for w in raw.split() if w]


def blocked(c: sqlite3.Connection) -> set:
    """Formas normalizadas de todas las palabras reservadas."""
    return {normalize(w) for w in words(c)} - {""}


def is_reserved(c: sqlite3.Connection, name: str) -> bool:
    return normalize(name) in blocked(c)


def check_username(c: sqlite3.Connection, username: str) -> None:
    if is_reserved(c, username):
        raise HTTPException(422, f"«{username}» es un nombre reservado: elige otro")


class WordsIn(BaseModel):
    words: List[str] = Field(default_factory=list, max_length=2000)


def register(app, d) -> None:
    def state(c: sqlite3.Connection) -> dict:
        current = words(c)
        return {"words": current, "default": get_setting(c, "reserved_words") is None, "count": len(current)}

    @app.get("/api/admin/reserved")
    def get_reserved(_: d.Admin, c: d.Conn):
        return state(c)

    @app.put("/api/admin/reserved")
    def put_reserved(body: WordsIn, _: d.Admin, c: d.Conn):
        clean = []
        for w in body.words:
            w = w.strip().lower()
            if not w:
                continue
            if not WORD_RE.match(w):
                raise HTTPException(422, f"«{w}» no es válido: sólo minúsculas, números y guiones")
            if w not in clean:
                clean.append(w)
        set_setting(c, "reserved_words", " ".join(sorted(clean)))
        return state(c)

    @app.delete("/api/admin/reserved")
    def reset_reserved(_: d.Admin, c: d.Conn):
        """Vuelve a la lista por defecto."""
        c.execute("DELETE FROM settings WHERE key = 'reserved_words'")
        return state(c)

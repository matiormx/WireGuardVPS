"""Configuración del panel, leída de variables de entorno (.env de docker compose)."""
from __future__ import annotations

import ipaddress
import os
import secrets
from dataclasses import dataclass
from pathlib import Path


def _env(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip()
    return value or default


def _env_int(name: str, default: int) -> int:
    raw = _env(name, str(default))
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} debe ser un entero (valor: {raw!r})") from exc


def _env_bool(name: str, default: bool) -> bool:
    return _env(name, "true" if default else "false").lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    wg_conf_dir: Path
    wg_interface: str
    wg_subnet: ipaddress.IPv4Network
    server_address: ipaddress.IPv4Interface
    wg_port: int
    endpoint: str
    dns: str
    mtu: int
    keepalive: int
    tenant_prefix: int
    firewall_hook: str
    session_secret: str
    session_hours: int
    admin_user: str
    admin_password: str
    cookie_secure: bool

    @property
    def tenant_capacity(self) -> int:
        """Número de redes de cliente disponibles (el bloque 0 es del servidor)."""
        return 2 ** (self.tenant_prefix - self.wg_subnet.prefixlen) - 1


def load_settings() -> Settings:
    subnet = ipaddress.ip_network(_env("WG_SUBNET", "10.252.0.0/16"), strict=True)
    if not isinstance(subnet, ipaddress.IPv4Network):
        raise ValueError("WG_SUBNET debe ser una red IPv4")
    server = ipaddress.ip_interface(_env("WG_SERVER_ADDRESS", f"{subnet[1]}/{subnet.prefixlen}"))
    tenant_prefix = _env_int("TENANT_PREFIX", 24)
    if not subnet.prefixlen < tenant_prefix <= 30:
        raise ValueError("TENANT_PREFIX debe ser mayor que el prefijo de WG_SUBNET y <= 30")
    first_block = next(subnet.subnets(new_prefix=tenant_prefix))
    if server.ip not in first_block:
        raise ValueError(f"WG_SERVER_ADDRESS debe estar en el bloque reservado {first_block}")

    secret = _env("SESSION_SECRET", "")
    if not secret:
        # Sin secreto persistente las sesiones caducan en cada reinicio.
        secret = secrets.token_hex(32)

    return Settings(
        data_dir=Path(_env("DATA_DIR", "/data")),
        wg_conf_dir=Path(_env("WG_CONF_DIR", "/etc/wireguard")),
        wg_interface=_env("WG_INTERFACE", "wg0"),
        wg_subnet=subnet,
        server_address=ipaddress.IPv4Interface(f"{server.ip}/{subnet.prefixlen}"),
        wg_port=_env_int("WG_PORT", 51820),
        endpoint=_env("WG_ENDPOINT", "127.0.0.1"),
        dns=_env("WG_DNS", "1.1.1.1, 1.0.0.1"),
        mtu=_env_int("WG_MTU", 1420),
        keepalive=_env_int("WG_KEEPALIVE", 25),
        tenant_prefix=tenant_prefix,
        firewall_hook=_env("FIREWALL_HOOK", "/usr/local/sbin/wgp-firewall"),
        session_secret=secret,
        session_hours=_env_int("SESSION_HOURS", 12),
        admin_user=_env("ADMIN_USER", "admin"),
        admin_password=_env("ADMIN_PASSWORD", "admin"),
        cookie_secure=_env_bool("COOKIE_SECURE", False),
    )

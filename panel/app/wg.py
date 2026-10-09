"""Gestión de WireGuard: claves, direccionamiento, ficheros de configuración y estado.

Modelo de red
-------------
WG_SUBNET (p. ej. 10.252.0.0/16) se divide en bloques de TENANT_PREFIX (/24):
  * bloque 0  (10.252.0.0/24)  -> servidor (10.252.0.1)
  * bloque N  (10.252.N.0/24)  -> red privada del cliente N
Dentro de cada bloque la .1 queda reservada y los dispositivos reciben .2-.254.

El panel escribe tres cosas en /etc/wireguard (montado desde el host):
  * wg0.conf             configuración completa (la usa wg-quick@wg0 al arrancar)
  * wgp/tenants.list     un grupo por cliente activo: su red y las LAN de sus routers
                         (separadas por espacios); el tráfico sólo se permite dentro del grupo
  * wgp/dns.list         redes de clientes con filtrado DNS: el host redirige su
                         DNS (puerto 53) al resolver y bloquea DNS-over-TLS
  * wgp/apply.stamp      marca temporal; su escritura dispara en el host la
                         unidad systemd que resincroniza el firewall
y aplica los peers en caliente con `wg syncconf` (sin cortar sesiones).

El firewall lo construye el host (wgp-firewall): el tráfico wg0->wg0 sólo se
acepta si origen y destino están en la MISMA red de cliente; el resto se descarta.
"""
from __future__ import annotations

import base64
import ipaddress
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .config import Settings
from .db import Database, get_setting
from .dnsfilter import tenant_filtering_active

log = logging.getLogger("wgp.wg")

ONLINE_WINDOW = 180  # s desde el último handshake para considerar un peer en línea


# --------------------------------------------------------------------------- claves
def generate_keypair() -> tuple[str, str]:
    key = X25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(private).decode(), base64.b64encode(public).decode()


def generate_psk() -> str:
    return base64.b64encode(os.urandom(32)).decode()


# ---------------------------------------------------------------------- direccionamiento
def tenant_network(settings: Settings, net_index: int) -> ipaddress.IPv4Network:
    if not 1 <= net_index <= settings.tenant_capacity:
        raise ValueError(f"Índice de red fuera de rango: {net_index}")
    size = 2 ** (32 - settings.tenant_prefix)
    base = int(settings.wg_subnet.network_address) + net_index * size
    return ipaddress.IPv4Network((base, settings.tenant_prefix))


def device_capacity(settings: Settings) -> int:
    # hosts utilizables menos la .1 reservada
    return 2 ** (32 - settings.tenant_prefix) - 3


def next_free_net_index(c: sqlite3.Connection, settings: Settings) -> int | None:
    used = {r[0] for r in c.execute("SELECT net_index FROM tenants")}
    for idx in range(1, settings.tenant_capacity + 1):
        if idx not in used:
            return idx
    return None


def next_free_ip(c: sqlite3.Connection, settings: Settings, net_index: int) -> str | None:
    net = tenant_network(settings, net_index)
    used = {r[0] for r in c.execute("SELECT ip FROM devices")}
    hosts = net.hosts()
    next(hosts, None)  # .1 reservada
    for ip in hosts:
        if str(ip) not in used:
            return str(ip)
    return None


# ---------------------------------------------------------------------------- render
_UNSAFE = re.compile(r"[\x00-\x1f\x7f]")


def _comment(text: str) -> str:
    return _UNSAFE.sub(" ", text)


def _endpoint(settings: Settings, host: str | None = None) -> str:
    host = host or settings.endpoint
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # IPv6 literal
    return f"{host}:{settings.wg_port}"


def parse_lans(text: str | None) -> list[str]:
    return [x for x in (text or "").split() if x]


def endpoint_host(c: sqlite3.Connection, settings: Settings) -> str:
    """Endpoint de los dispositivos: nombre configurado en Ajustes o, si no, WG_ENDPOINT (IP)."""
    return get_setting(c, "wg_endpoint") or settings.endpoint


def tenant_lans(c: sqlite3.Connection, tenant_id: int, exclude_device: int | None = None) -> list[str]:
    """LAN de los routers activos de un cliente (para AllowedIPs de sus dispositivos)."""
    out: list[str] = []
    for r in c.execute("SELECT id, lan_networks FROM devices WHERE tenant_id = ? AND kind = 'router' AND enabled = 1",
                       (tenant_id,)):
        if r["id"] != exclude_device:
            out += parse_lans(r["lan_networks"])
    return out


@dataclass
class Peer:
    tenant: str
    name: str
    ip: str
    public_key: str
    preshared_key: str
    lans: tuple[str, ...] = ()


def render_server_conf(settings: Settings, private_key: str, peers: list[Peer], *, full: bool = True) -> str:
    """full=True -> wg0.conf para wg-quick; full=False -> formato `wg syncconf`."""
    lines = ["[Interface]"]
    if full:
        lines += [
            "# Generado por el panel WireGuard Multi-Tenant. No editar a mano.",
            f"Address = {settings.server_address}",
            f"MTU = {settings.mtu}",
            f"PostUp = {settings.firewall_hook} up %i",
            f"PostDown = {settings.firewall_hook} down %i",
        ]
    lines += [f"ListenPort = {settings.wg_port}", f"PrivateKey = {private_key}", ""]
    for p in peers:
        if full:
            lines.append(f"# {_comment(p.tenant)} / {_comment(p.name)}")
        lines += [
            "[Peer]",
            f"PublicKey = {p.public_key}",
            f"PresharedKey = {p.preshared_key}",
            f"AllowedIPs = {', '.join([f'{p.ip}/32', *p.lans])}",
            "",
        ]
    return "\n".join(lines)


def render_client_conf(settings: Settings, server_public: str, tenant: sqlite3.Row, device: sqlite3.Row,
                       search: list[str] | tuple[str, ...] = (), endpoint: str | None = None,
                       lans: list[str] | tuple[str, ...] = ()) -> str:
    """`lans`: redes LAN de los routers del cliente (sin las del propio dispositivo)."""
    net = tenant_network(settings, tenant["net_index"])
    is_router = device["kind"] == "router"
    # full tunnel: todo el tráfico (y ::/0 para evitar fugas IPv6);
    # split tunnel: la red del cliente, las LAN de sus routers y el servidor (DNS).
    # Un router siempre va en split: su LAN sale a Internet por su propia conexión.
    if device["full_tunnel"] and not is_router:
        allowed = "0.0.0.0/0, ::/0"
    else:
        allowed = ", ".join([str(net), f"{settings.server_address.ip}/32", *lans])
    lines = [
        "[Interface]",
        f"# {_comment(tenant['name'])} / {_comment(device['name'])}",
        f"PrivateKey = {device['private_key']}",
        f"Address = {device['ip']}/32",
    ]
    if not is_router and (device["full_tunnel"] or settings.dns_enabled):
        # Los sufijos de búsqueda van en la misma línea DNS (wg-quick y las apps
        # oficiales los tratan como dominios de búsqueda): «nas» -> «nas.vpn».
        dns = [settings.client_dns] + (list(search) if settings.dns_enabled else [])
        lines.append(f"DNS = {', '.join(dns)}")
    lines += [
        f"MTU = {settings.mtu}",
        "",
        "[Peer]",
        f"PublicKey = {server_public}",
        f"PresharedKey = {device['preshared_key']}",
        f"Endpoint = {_endpoint(settings, endpoint)}",
        f"AllowedIPs = {allowed}",
        f"PersistentKeepalive = {settings.keepalive}",
        "",
    ]
    return "\n".join(lines)


def render_mikrotik(settings: Settings, server_public: str, tenant: sqlite3.Row, device: sqlite3.Row,
                    endpoint: str | None = None, lans: list[str] | tuple[str, ...] = ()) -> str:
    """Comandos RouterOS 7 para conectar un MikroTik como router del cliente (site-to-site)."""
    net = tenant_network(settings, tenant["net_index"])
    host = endpoint or settings.endpoint
    own = parse_lans(device["lan_networks"])
    allowed = ",".join([str(net), f"{settings.server_address.ip}/32", *lans])
    lines = [
        f"# WireGuard Cloud - {_comment(tenant['name'])} / {_comment(device['name'])}",
        "# Pegar en el Terminal de RouterOS 7 (Winbox > New Terminal o SSH).",
        f"# LAN publicada: {', '.join(own) or '(ninguna)'}",
        f'/interface wireguard add name=wg-cloud mtu={settings.mtu} private-key="{device["private_key"]}" comment="WireGuard Cloud"',
        f'/interface wireguard peers add interface=wg-cloud public-key="{server_public}" preshared-key="{device["preshared_key"]}" '
        f"endpoint-address={host} endpoint-port={settings.wg_port} allowed-address={allowed} "
        f"persistent-keepalive={settings.keepalive}s comment=\"WireGuard Cloud\"",
        f"/ip address add address={device['ip']}/{net.prefixlen} interface=wg-cloud comment=\"WireGuard Cloud\"",
        f"/ip route add dst-address={settings.server_address.ip}/32 gateway=wg-cloud comment=\"WireGuard Cloud\"",
    ]
    lines += [f'/ip route add dst-address={lan} gateway=wg-cloud comment="WireGuard Cloud"' for lan in lans]
    lines += [
        "# Que el tráfico del túnel se trate como LAN (cortafuegos por defecto de MikroTik):",
        '/interface list member add interface=wg-cloud list=LAN comment="WireGuard Cloud"',
        "",
    ]
    return "\n".join(lines)


def _atomic_write(path: Path, content: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


# --------------------------------------------------------------------------- manager
class WireGuardManager:
    def __init__(self, settings: Settings, database: Database) -> None:
        self.settings = settings
        self.db = database
        self._lock = threading.Lock()
        self.conf_path = settings.wg_conf_dir / f"{settings.wg_interface}.conf"
        self.fw_dir = settings.wg_conf_dir / "wgp"
        self.tenants_list = self.fw_dir / "tenants.list"
        self.dns_list = self.fw_dir / "dns.list"
        self.stamp = self.fw_dir / "apply.stamp"

    def server_public_key(self) -> str:
        with self.db.conn() as c:
            return get_setting(c, "server_public_key") or ""

    def interface_up(self) -> bool:
        return Path(f"/sys/class/net/{self.settings.wg_interface}").exists()

    def apply(self) -> bool:
        """Regenera ficheros y aplica peers. Devuelve True si se aplicó en caliente."""
        with self._lock:
            with self.db.conn() as c:
                private = get_setting(c, "server_private_key") or ""
                rows = c.execute(
                    """SELECT d.name, d.ip, d.public_key, d.preshared_key, d.kind, d.lan_networks,
                              t.name AS tenant, t.net_index
                       FROM devices d JOIN tenants t ON t.id = d.tenant_id
                       WHERE d.enabled = 1 AND t.enabled = 1 ORDER BY t.net_index, d.id"""
                ).fetchall()
                active = c.execute(
                    "SELECT net_index, dns_filters, dns_deny FROM tenants WHERE enabled = 1 ORDER BY net_index"
                ).fetchall()
            lans_by_tenant: dict[int, list[str]] = {}
            for r in rows:
                if r["kind"] == "router":
                    lans_by_tenant.setdefault(r["net_index"], []).extend(parse_lans(r["lan_networks"]))
            # Un grupo por cliente: su /24 y las LAN de sus routers se ven entre sí.
            groups = [" ".join([str(tenant_network(self.settings, r["net_index"])), *lans_by_tenant.get(r["net_index"], [])])
                      for r in active]
            dns_nets = [tenant_network(self.settings, r["net_index"]) for r in active
                        if self.settings.dns_enabled and tenant_filtering_active(r)]
            peers = [Peer(r["tenant"], r["name"], r["ip"], r["public_key"], r["preshared_key"],
                          tuple(parse_lans(r["lan_networks"])) if r["kind"] == "router" else ()) for r in rows]
            all_lans = {lan for lans in lans_by_tenant.values() for lan in lans}

            _atomic_write(self.conf_path, render_server_conf(self.settings, private, peers), 0o600)
            _atomic_write(self.tenants_list, "".join(f"{g}\n" for g in groups), 0o644)
            _atomic_write(self.dns_list, "".join(f"{n}\n" for n in dns_nets), 0o644)
            # Escritura in situ (IN_CLOSE_WRITE) para disparar la unidad .path del host.
            with open(self.stamp, "w") as fh:
                fh.write(f"{time.time():.3f}\n")
            applied = self._syncconf(render_server_conf(self.settings, private, peers, full=False))
            # `wg syncconf` no toca la tabla de rutas: las LAN de los routers se enrutan aquí.
            self._sync_routes(all_lans)
            return applied

    def _ip(self, *args: str) -> subprocess.CompletedProcess | None:
        if shutil.which("ip") is None:
            return None
        try:
            return subprocess.run(["ip", *args], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return None

    def _sync_routes(self, desired: set[str]) -> None:
        """Rutas por wg0 hacia las LAN de los routers: añade las nuevas y quita las que sobran."""
        iface = self.settings.wg_interface
        if not self.interface_up():
            return
        res = self._ip("-4", "route", "show", "dev", iface)
        if res is None or res.returncode != 0:
            return
        current = set()
        for line in res.stdout.splitlines():
            parts = line.split()
            if not parts or parts[0] == "default" or ("proto" in parts and parts[parts.index("proto") + 1] == "kernel"):
                continue  # la ruta de la propia subred del túnel la gestiona el kernel
            current.add(parts[0])
        for dst in sorted(desired):
            self._ip("route", "replace", dst, "dev", iface)
        for dst in sorted(current - desired):
            self._ip("route", "del", dst, "dev", iface)

    def host_networks(self) -> list:
        """Redes ya usadas por el servidor (proveedor, Docker...) que una LAN no puede pisar."""
        out = []
        for args in (("-4", "-o", "addr", "show"), ("-4", "route", "show")):
            res = self._ip(*args)
            if res is None or res.returncode != 0:
                continue
            for line in res.stdout.splitlines():
                parts = line.split()
                if self.settings.wg_interface in parts:
                    continue
                token = parts[3] if args[2] == "addr" and len(parts) > 3 else (parts[0] if parts else "")
                if token == "default":
                    continue
                try:
                    net = ipaddress.ip_network(token, strict=False)
                except ValueError:
                    continue
                if isinstance(net, ipaddress.IPv4Network) and not net.is_loopback:
                    out.append(net)
        return out

    def _syncconf(self, content: str) -> bool:
        if shutil.which("wg") is None or not self.interface_up():
            log.info("Interfaz %s no disponible; el host la levantará con wg0.conf", self.settings.wg_interface)
            return False
        fd, tmp = tempfile.mkstemp(dir=self.settings.data_dir, prefix=".sync.")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(content)
            os.chmod(tmp, 0o600)
            res = subprocess.run(
                ["wg", "syncconf", self.settings.wg_interface, tmp],
                capture_output=True, text=True, timeout=15,
            )
        finally:
            os.unlink(tmp)
        if res.returncode != 0:
            log.error("wg syncconf falló: %s", res.stderr.strip())
            return False
        return True

    def stats(self) -> dict[str, dict]:
        """Estado por clave pública: endpoint, último handshake, rx/tx, online."""
        if shutil.which("wg") is None or not self.interface_up():
            return {}
        try:
            res = subprocess.run(
                ["wg", "show", self.settings.wg_interface, "dump"],
                capture_output=True, text=True, timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return {}
        if res.returncode != 0:
            return {}
        now = time.time()
        out: dict[str, dict] = {}
        for line in res.stdout.splitlines()[1:]:  # la primera línea es la interfaz
            f = line.split("\t")
            if len(f) < 8:
                continue
            handshake = int(f[4]) if f[4].isdigit() else 0
            out[f[0]] = {
                "endpoint": None if f[2] == "(none)" else f[2],
                "last_handshake": handshake or None,
                "rx": int(f[5]) if f[5].isdigit() else 0,
                "tx": int(f[6]) if f[6].isdigit() else 0,
                "online": bool(handshake) and now - handshake < ONLINE_WINDOW,
            }
        return out

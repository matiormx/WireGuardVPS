"""Salidas por país: servidores de salida a Internet en otros países.

Los dispositivos siguen conectándose al servidor principal (la red privada,
el DNS y los filtros no cambian). Cada servidor de salida es un VPS sencillo
unido al principal por un túnel WireGuard propio (wgxN, red 169.254.252.x/30);
el tráfico a Internet de los dispositivos que lo elijan sale por él con la IP
de ese país.

  * El panel escribe /etc/wireguard/wgxN.conf (Table = off), wgp/exits.list
    ("wgxN tabla") y wgp/exit_routes.list ("IP wgxN"); el host (wgp-firewall)
    levanta los túneles y crea el enrutamiento por origen.
  * Si una salida deja de responder, sus dispositivos vuelven a salir por el
    servidor principal (salvo que se desactive esa opción: «sin salida»).
  * El nodo de salida se instala con un comando y un token que genera el panel
    (contiene su clave privada: se muestra sólo al administrador).

Sin `from __future__ import annotations`: FastAPI evalúa las dependencias de `deps`.
"""
import base64
import ipaddress
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .db import get_setting, set_setting

log = logging.getLogger("wgp.exits")

LINK_NET = "169.254.252."
TABLE_BASE = 200
MAX_EXITS = 60
EXIT_PORT = 51821
HEALTH_WINDOW = 180
MARKER = "# Generado por el panel WireGuard Multi-Tenant (salida por país)"
COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
REPO_RAW = os.environ.get("WGP_REPO_RAW", "https://raw.githubusercontent.com/matiormx/WireGuardVps/main")


def hub_ip(idx: int) -> str:
    return f"{LINK_NET}{4 * idx + 1}"


def exit_ip(idx: int) -> str:
    return f"{LINK_NET}{4 * idx + 2}"


def iface(idx: int) -> str:
    return f"wgx{idx}"


def render_hub_conf(row: sqlite3.Row, mtu: int, hook: str) -> str:
    """Túnel del servidor principal hacia una salida. Table = off: el host enruta por origen."""
    name = re.sub(r"[\r\n]", " ", row["name"])
    return "\n".join([
        MARKER,
        f"# {name} ({row['country']})",
        "[Interface]",
        f"Address = {hub_ip(row['idx'])}/30",
        f"PrivateKey = {row['hub_private']}",
        f"MTU = {mtu}",
        "Table = off",
        f"PostUp = {hook} sync",
        "",
        "[Peer]",
        f"PublicKey = {row['exit_public']}",
        f"Endpoint = {row['host']}:{row['port']}",
        "AllowedIPs = 0.0.0.0/0",
        "PersistentKeepalive = 25",
        "",
    ])


def install_token(row: sqlite3.Row, hub_public: str, subnet: str) -> str:
    label = re.sub(r"[^A-Za-z0-9 ._-]", "", row["name"])[:40] or "salida"
    raw = "|".join(["v1", iface(row["idx"]), row["exit_private"], hub_public, f"{exit_ip(row['idx'])}/30",
                    hub_ip(row["idx"]), subnet, str(row["port"]), label])
    return base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode()


def install_command(token: str) -> str:
    return f"curl -fsSL {REPO_RAW}/install.sh | sudo bash -s -- exit-node {token}"


def tunnel_stats(idx: int) -> dict:
    """Estado del túnel wgxN visto desde el servidor principal."""
    name = iface(idx)
    out = {"up": Path(f"/sys/class/net/{name}").exists(), "handshake": None, "rx": 0, "tx": 0, "healthy": False}
    if not out["up"] or shutil.which("wg") is None:
        return out
    try:
        res = subprocess.run(["wg", "show", name, "dump"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return out
    lines = res.stdout.splitlines()[1:] if res.returncode == 0 else []
    if lines:
        f = lines[0].split("\t")
        if len(f) >= 7:
            hs = int(f[4]) if f[4].isdigit() else 0
            out.update(handshake=hs or None, rx=int(f[5] or 0), tx=int(f[6] or 0),
                       healthy=bool(hs) and time.time() - hs < HEALTH_WINDOW)
    return out


def effective_exits(c: sqlite3.Connection) -> list[tuple[str, int]]:
    """(IP del dispositivo, id de salida) para los dispositivos que salen por otro país."""
    rows = c.execute(
        """SELECT d.ip, COALESCE(d.exit_id, t.exit_id, 0) AS exit_id
           FROM devices d JOIN tenants t ON t.id = d.tenant_id
           WHERE d.enabled = 1 AND t.enabled = 1 AND t.allow_exits = 1 AND d.full_tunnel = 1 AND d.kind = 'device'"""
    ).fetchall()
    return [(r["ip"], r["exit_id"]) for r in rows if r["exit_id"]]


def write_files(c: sqlite3.Connection, settings, write) -> set[int]:
    """Escribe los túneles y las listas para el host. Devuelve las salidas sanas usadas."""
    exits = c.execute("SELECT * FROM exits WHERE enabled = 1 ORDER BY idx").fetchall()
    conf_dir: Path = settings.wg_conf_dir
    wanted = set()
    for e in exits:
        path = conf_dir / f"{iface(e['idx'])}.conf"
        write(path, render_hub_conf(e, settings.mtu, settings.firewall_hook), 0o600)
        wanted.add(path.name)
    for path in conf_dir.glob("wgx*.conf"):
        if path.name not in wanted:
            try:
                if path.read_text().startswith(MARKER):
                    path.unlink()
            except OSError:
                pass
    by_id = {e["id"]: e for e in exits}
    usable = {e["id"] for e in exits if not e["failover"] or tunnel_stats(e["idx"])["healthy"]}
    routes = [f"{ip} {iface(by_id[x]['idx'])}" for ip, x in effective_exits(c) if x in usable]
    fw = conf_dir / "wgp"
    write(fw / "exits.list", "".join(f"{iface(e['idx'])} {TABLE_BASE + e['idx']}\n" for e in exits), 0o644)
    write(fw / "exit_routes.list", "".join(f"{r}\n" for r in routes), 0o644)
    return usable


# --------------------------------------------------------------------------- API
class ExitIn(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    country: str = Field(pattern=r"^[A-Za-z]{2}$")
    host: str = Field(min_length=3, max_length=253)
    port: int = Field(default=EXIT_PORT, ge=1024, le=65535)


class ExitUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=40)
    country: str | None = Field(default=None, pattern=r"^[A-Za-z]{2}$")
    host: str | None = Field(default=None, min_length=3, max_length=253)
    port: int | None = Field(default=None, ge=1024, le=65535)
    enabled: bool | None = None
    failover: bool | None = None


class MainLocationIn(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    country: str = Field(pattern=r"^[A-Za-z]{2}$")


class DefaultExitIn(BaseModel):
    exit_id: int = Field(ge=0)
    tenant_id: int | None = None


def register(app: FastAPI, d) -> None:
    settings = d.settings

    def clean_host(raw: str) -> str:
        raw = raw.strip().lower()
        try:
            return str(ipaddress.IPv4Address(raw))
        except ValueError:
            host = d.normalize_host(raw)
            if not host:
                raise HTTPException(422, "Dirección no válida: IP pública o nombre del servidor de salida") from None
            return host

    def main_location(c: sqlite3.Connection) -> dict:
        return {"name": get_setting(c, "main_exit_name") or "Servidor principal",
                "country": get_setting(c, "main_exit_country") or ""}

    def exit_json(c: sqlite3.Connection, e: sqlite3.Row, admin: bool) -> dict:
        st = tunnel_stats(e["idx"])
        out = {"id": e["id"], "name": e["name"], "country": e["country"], "enabled": bool(e["enabled"]),
               "online": st["healthy"]}
        if admin:
            used = c.execute("""SELECT COUNT(*) FROM devices d JOIN tenants t ON t.id = d.tenant_id
                                WHERE COALESCE(d.exit_id, t.exit_id, 0) = ?""", (e["id"],)).fetchone()[0]
            out.update(host=e["host"], port=e["port"], failover=bool(e["failover"]), created_at=e["created_at"],
                       iface=iface(e["idx"]), handshake=st["handshake"], rx=st["rx"], tx=st["tx"], up=st["up"],
                       devices=used)
        return out

    def exit_or_404(c: sqlite3.Connection, exit_id: int) -> sqlite3.Row:
        row = c.execute("SELECT * FROM exits WHERE id = ?", (exit_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Salida no encontrada")
        return row

    @app.get("/api/admin/exits")
    def list_exits(_: d.Admin, c: d.Conn):
        rows = c.execute("SELECT * FROM exits ORDER BY name COLLATE NOCASE").fetchall()
        return {"main": main_location(c), "exits": [exit_json(c, e, True) for e in rows]}

    @app.post("/api/admin/exits", status_code=201)
    def create_exit(body: ExitIn, _: d.Admin, c: d.Conn):
        used = {r[0] for r in c.execute("SELECT idx FROM exits")}
        idx = next((i for i in range(1, MAX_EXITS + 1) if i not in used), None)
        if idx is None:
            raise HTTPException(409, f"Máximo {MAX_EXITS} salidas")
        hub_private, hub_public = d.keypair()
        exit_private, exit_public = d.keypair()
        cur = c.execute(
            """INSERT INTO exits (name, country, host, port, idx, hub_private, hub_public, exit_private, exit_public, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (body.name.strip(), body.country.upper(), clean_host(body.host), body.port, idx,
             hub_private, hub_public, exit_private, exit_public, int(time.time())))
        c.commit()
        d.apply_wg()
        row = exit_or_404(c, cur.lastrowid)
        return {**exit_json(c, row, True), **install_info(row)}

    def install_info(row: sqlite3.Row) -> dict:
        token = install_token(row, row["hub_public"], str(settings.wg_subnet))
        return {"command": install_command(token), "port": row["port"]}

    @app.get("/api/admin/exits/{exit_id}/install")
    def exit_install(exit_id: int, _: d.Admin, c: d.Conn):
        return install_info(exit_or_404(c, exit_id))

    @app.patch("/api/admin/exits/{exit_id}")
    def update_exit(exit_id: int, body: ExitUpdate, _: d.Admin, c: d.Conn):
        exit_or_404(c, exit_id)
        if body.name is not None:
            c.execute("UPDATE exits SET name = ? WHERE id = ?", (body.name.strip(), exit_id))
        if body.country is not None:
            c.execute("UPDATE exits SET country = ? WHERE id = ?", (body.country.upper(), exit_id))
        if body.host is not None:
            c.execute("UPDATE exits SET host = ? WHERE id = ?", (clean_host(body.host), exit_id))
        if body.port is not None:
            c.execute("UPDATE exits SET port = ? WHERE id = ?", (body.port, exit_id))
        if body.enabled is not None:
            c.execute("UPDATE exits SET enabled = ? WHERE id = ?", (int(body.enabled), exit_id))
        if body.failover is not None:
            c.execute("UPDATE exits SET failover = ? WHERE id = ?", (int(body.failover), exit_id))
        c.commit()
        d.apply_wg()
        return exit_json(c, exit_or_404(c, exit_id), True)

    @app.delete("/api/admin/exits/{exit_id}")
    def delete_exit(exit_id: int, _: d.Admin, c: d.Conn):
        exit_or_404(c, exit_id)
        c.execute("UPDATE devices SET exit_id = NULL WHERE exit_id = ?", (exit_id,))
        c.execute("UPDATE tenants SET exit_id = NULL WHERE exit_id = ?", (exit_id,))
        c.execute("DELETE FROM exits WHERE id = ?", (exit_id,))
        c.commit()
        d.apply_wg()
        return {"ok": True}

    @app.put("/api/admin/main-location")
    def put_main(body: MainLocationIn, _: d.Admin, c: d.Conn):
        set_setting(c, "main_exit_name", body.name.strip())
        set_setting(c, "main_exit_country", body.country.upper())
        return main_location(c)

    # ---------------------------------------------------------------- clientes y usuarios
    @app.get("/api/exits")
    def available(p: d.Anyone, c: d.Conn, tenant_id: int | None = None):
        tid = tenant_id if p.is_admin else p.tenant_id
        t = d.tenant_or_404(c, tid) if tid else None
        rows = c.execute("SELECT * FROM exits WHERE enabled = 1 ORDER BY name COLLATE NOCASE").fetchall()
        return {"main": main_location(c), "exits": [exit_json(c, e, False) for e in rows],
                "allowed": bool(t["allow_exits"]) if t else True, "tenant_default": (t["exit_id"] or 0) if t else 0}

    @app.put("/api/exits/default")
    def set_default(body: DefaultExitIn, p: d.User, c: d.Conn):
        tid = d.scope_tenant(p, body.tenant_id)
        t = d.tenant_or_404(c, tid)
        check_exit(c, t, body.exit_id)
        c.execute("UPDATE tenants SET exit_id = ? WHERE id = ?", (body.exit_id or None, tid))
        c.commit()
        d.apply_wg()
        return available(p, c, tid)

    def check_exit(c: sqlite3.Connection, tenant: sqlite3.Row, exit_id: int | None) -> None:
        """exit_id: None = la del cliente, 0 = servidor principal, >0 = salida."""
        if not exit_id:
            return
        if not tenant["allow_exits"]:
            raise HTTPException(403, "Tu plan no incluye salidas por país")
        if not c.execute("SELECT 1 FROM exits WHERE id = ? AND enabled = 1", (exit_id,)).fetchone():
            raise HTTPException(422, "Salida no disponible")

    d.check_exit = check_exit

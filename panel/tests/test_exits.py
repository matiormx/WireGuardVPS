from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from app import exits
from app.main import create_app

H = {"X-WGP": "1"}


@pytest.fixture()
def admin(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("WG_CONF_DIR", str(tmp_path / "wireguard"))
    monkeypatch.setenv("WG_ENDPOINT", "203.0.113.10")
    monkeypatch.setenv("SESSION_SECRET", "x")
    monkeypatch.setenv("DNS_ENABLED", "false")
    monkeypatch.setenv("CADDY_ADMIN", "")
    monkeypatch.setattr("app.wg.WireGuardManager.host_networks", lambda self: [])
    health = {"ok": set()}
    monkeypatch.setattr(exits, "tunnel_stats", lambda idx: {"up": True, "handshake": None, "rx": 0, "tx": 0,
                                                             "healthy": idx in health["ok"]})
    with TestClient(create_app()) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": "admin"}, headers=H)
        c.post("/api/me/password", json={"current": "admin", "new": "AdminPass1"}, headers=H)
        c.wg = tmp_path / "wireguard"
        c.health = health
        yield c


def routes(c):
    return (c.wg / "wgp" / "exit_routes.list").read_text().splitlines()


def decode(cmd):
    token = cmd.rsplit(" ", 1)[1]
    return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode().split("|")


def test_exits_routing_and_failover(admin):
    assert admin.post("/api/admin/exits", json={"name": "Alemania", "country": "de", "host": "no válido!"}, headers=H).status_code == 422
    de = admin.post("/api/admin/exits", json={"name": "Alemania", "country": "de", "host": "DE1.Ejemplo.com"}, headers=H).json()
    us = admin.post("/api/admin/exits", json={"name": "EE. UU.", "country": "US", "host": "198.51.100.20", "port": 51900}, headers=H).json()
    assert de["country"] == "DE" and de["iface"] == "wgx1" and us["iface"] == "wgx2"
    f = decode(de["command"])
    assert de["command"].startswith("curl -fsSL https://raw.githubusercontent.com/") and "exit-node" in de["command"]
    assert f[:2] == ["v1", "wgx1"] and f[4:] == ["169.254.252.6/30", "169.254.252.5", "10.252.0.0/16", "51821", "Alemania"]
    conf = (admin.wg / "wgx1.conf").read_text()
    assert "Endpoint = de1.ejemplo.com:51821" in conf and "Table = off" in conf and "Address = 169.254.252.5/30" in conf
    assert f"PublicKey = {de['id'] and decode(de['command'])[3]}" not in conf  # la clave pública del hub no va en su propio conf
    assert "PostUp = /usr/local/sbin/wgp-firewall sync" in conf
    assert (admin.wg / "wgp" / "exits.list").read_text() == "wgx1 201\nwgx2 202\n"

    t = admin.post("/api/admin/tenants", json={"name": "Acme", "username": "acme", "password": "Password1"}, headers=H).json()
    d1 = admin.post("/api/devices", json={"name": "Portátil", "tenant_id": t["id"], "exit_id": de["id"]}, headers=H).json()
    d2 = admin.post("/api/devices", json={"name": "Móvil", "tenant_id": t["id"]}, headers=H).json()
    d3 = admin.post("/api/devices", json={"name": "Solo red", "tenant_id": t["id"], "full_tunnel": False, "exit_id": us["id"]}, headers=H).json()
    assert admin.post("/api/devices", json={"name": "X", "tenant_id": t["id"], "exit_id": 999}, headers=H).status_code == 422
    assert routes(admin) == []                    # la salida aún no responde: todos por el principal
    admin.health["ok"] = {1, 2}
    admin.app.state.wg.refresh_exits()
    assert routes(admin) == [f"{d1['ip']} wgx1"]  # d3 no envía su Internet por la VPN
    # Salida por defecto del cliente; un dispositivo puede forzar el principal (0) o heredar (-1)
    admin.put("/api/exits/default", json={"exit_id": us["id"], "tenant_id": t["id"]}, headers=H)
    assert sorted(routes(admin)) == sorted([f"{d1['ip']} wgx1", f"{d2['ip']} wgx2"])
    admin.patch(f"/api/devices/{d2['id']}", json={"exit_id": 0}, headers=H)
    assert routes(admin) == [f"{d1['ip']} wgx1"]
    admin.patch(f"/api/devices/{d1['id']}", json={"exit_id": -1}, headers=H)
    assert routes(admin) == [f"{d1['ip']} wgx2"]
    # Caída de una salida: failover al principal; sin failover, se mantiene («kill switch»)
    admin.health["ok"] = {1}
    assert admin.app.state.wg.refresh_exits() == ({us["id"]}, set())
    assert routes(admin) == []
    admin.patch(f"/api/admin/exits/{us['id']}", json={"failover": False}, headers=H)
    assert routes(admin) == [f"{d1['ip']} wgx2"]
    # Plan sin salidas: todo por el principal y no se puede elegir
    admin.patch(f"/api/admin/tenants/{t['id']}", json={"allow_exits": False}, headers=H)
    assert routes(admin) == []
    assert admin.patch(f"/api/devices/{d2['id']}", json={"exit_id": de["id"]}, headers=H).status_code == 403
    admin.patch(f"/api/admin/tenants/{t['id']}", json={"allow_exits": True}, headers=H)
    # Desactivar y borrar
    admin.patch(f"/api/admin/exits/{us['id']}", json={"enabled": False}, headers=H)
    assert not (admin.wg / "wgx2.conf").exists() and (admin.wg / "wgp" / "exits.list").read_text() == "wgx1 201\n"
    admin.delete(f"/api/admin/exits/{de['id']}", headers=H)
    assert not (admin.wg / "wgx1.conf").exists()
    dev = {x["name"]: x for x in admin.get(f"/api/devices?tenant_id={t['id']}").json()}
    assert dev["Portátil"]["exit_id"] is None
    lst = admin.get("/api/admin/exits").json()
    assert [e["name"] for e in lst["exits"]] == ["EE. UU."] and lst["main"]["name"] == "Servidor principal"
    assert admin.put("/api/admin/main-location", json={"name": "España", "country": "es"}, headers=H).json() == {"name": "España", "country": "ES"}


def test_tenant_and_member_access(admin):
    de = admin.post("/api/admin/exits", json={"name": "Alemania", "country": "DE", "host": "198.51.100.30"}, headers=H).json()
    t = admin.post("/api/admin/tenants", json={"name": "Acme", "username": "acme", "password": "Temporal1"}, headers=H).json()
    boss = TestClient(admin.app)
    boss.post("/api/auth/login", json={"username": "acme", "password": "Temporal1"}, headers=H)
    boss.post("/api/me/password", json={"current": "Temporal1", "new": "Acme22222"}, headers=H)
    pub = boss.get("/api/exits").json()
    assert pub["allowed"] and pub["exits"] == [{"id": de["id"], "name": "Alemania", "country": "DE", "enabled": True, "online": False}]
    assert "host" not in str(pub) and boss.get("/api/admin/exits").status_code == 403
    assert boss.get(f"/api/admin/exits/{de['id']}/install").status_code == 403
    assert boss.put("/api/exits/default", json={"exit_id": de["id"]}, headers=H).json()["tenant_default"] == de["id"]
    boss.post("/api/members", json={"name": "Ana", "username": "ana", "password": "Temporal2"}, headers=H)
    ana = TestClient(admin.app)
    ana.post("/api/auth/login", json={"username": "ana", "password": "Temporal2"}, headers=H)
    ana.post("/api/me/password", json={"current": "Temporal2", "new": "AnaClave99"}, headers=H)
    dev = ana.post("/api/devices", json={"name": "iPhone", "exit_id": de["id"]}, headers=H).json()
    assert dev["exit_id"] == de["id"] and ana.get("/api/exits").json()["tenant_default"] == de["id"]
    assert ana.put("/api/exits/default", json={"exit_id": 0}, headers=H).status_code == 403


def test_exit_health_changes_are_reported(admin):
    de = admin.post("/api/admin/exits", json={"name": "Alemania", "country": "DE", "host": "198.51.100.30"}, headers=H).json()
    wgm = admin.app.state.wg
    assert wgm.refresh_exits() is None                    # primera lectura
    admin.health["ok"] = {1}
    assert wgm.refresh_exits() == (set(), {de["id"]})     # conectada
    assert wgm.refresh_exits() is None
    admin.health["ok"] = set()
    assert wgm.refresh_exits() == ({de["id"]}, set())     # caída
    sent = []
    n = admin.app.state.notifier
    n.deliver = lambda to, title, body, url="/": sent.append((to, title, body))
    n.on_exit_change({de["id"]}, set())
    assert sent and "Alemania" in sent[0][1] and "servidor principal" in sent[0][2]

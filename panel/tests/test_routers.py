from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

H = {"X-WGP": "1"}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("WG_CONF_DIR", str(tmp_path / "wireguard"))
    monkeypatch.setenv("WG_ENDPOINT", "203.0.113.10")
    monkeypatch.setenv("SESSION_SECRET", "x")
    monkeypatch.setenv("DNS_BIND", "127.0.0.1")
    monkeypatch.setenv("DNS_PORT", "0")
    monkeypatch.setattr("app.dnsfilter.ListStore.refresh", lambda self: None)
    # Redes del propio servidor (proveedor y Docker) que ninguna LAN puede pisar
    import ipaddress
    monkeypatch.setattr("app.wg.WireGuardManager.host_networks",
                        lambda self: [ipaddress.ip_network("172.17.0.0/16"), ipaddress.ip_network("10.0.0.0/24")])
    return tmp_path


@pytest.fixture()
def admin(env):
    with TestClient(create_app()) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": "admin"}, headers=H)
        c.post("/api/me/password", json={"current": "admin", "new": "AdminPass1"}, headers=H)
        yield c


def mk(c, username):
    return c.post("/api/admin/tenants", json={"name": username.title(), "username": username, "password": "Password1"}, headers=H).json()


def router(c, tid, lans, name="MikroTik oficina"):
    return c.post("/api/devices", json={"name": name, "tenant_id": tid, "kind": "router", "lan_networks": lans}, headers=H)


def test_router_validation(admin):
    a, b = mk(admin, "acme"), mk(admin, "globex")
    for bad, code in [(["8.8.8.0/24"], 422), (["10.252.5.0/24"], 422), (["192.168.1.0/31"], 422), (["no-red"], 422),
                      (["172.17.5.0/24"], 409), (["10.0.0.0/16"], 409), ([], 422),
                      (["192.168.88.0/24", "192.168.88.128/25"], 422)]:
        r = router(admin, a["id"], bad)
        assert r.status_code == code, (bad, r.text)
    r = router(admin, a["id"], ["192.168.88.7/24", "10.50.0.0/16"])
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["kind"] == "router" and d["lan_networks"] == ["192.168.88.0/24", "10.50.0.0/16"] and not d["full_tunnel"]
    # la misma LAN no puede estar en dos clientes (las rutas del servidor son globales)
    r = router(admin, b["id"], ["192.168.88.0/24"])
    assert r.status_code == 409 and "Acme" not in r.text
    # editar LAN; un dispositivo normal no tiene LAN
    assert admin.patch(f"/api/devices/{d['id']}", json={"lan_networks": ["192.168.77.0/24"]}, headers=H).json()["lan_networks"] == ["192.168.77.0/24"]
    phone = admin.post("/api/devices", json={"name": "iPhone", "tenant_id": a["id"], "full_tunnel": False}, headers=H).json()
    assert admin.patch(f"/api/devices/{phone['id']}", json={"lan_networks": ["192.168.66.0/24"]}, headers=H).status_code == 422
    # ahora 192.168.88.0/24 está libre para otro cliente
    assert router(admin, b["id"], ["192.168.88.0/24"]).status_code == 201


def test_router_configs_routes_and_groups(admin, env):
    a, b = mk(admin, "acme"), mk(admin, "globex")
    r = router(admin, a["id"], ["192.168.88.0/24"]).json()
    phone = admin.post("/api/devices", json={"name": "iPhone", "tenant_id": a["id"], "full_tunnel": False}, headers=H).json()
    full = admin.post("/api/devices", json={"name": "Portátil", "tenant_id": a["id"]}, headers=H).json()
    other = admin.post("/api/devices", json={"name": "PC", "tenant_id": b["id"], "full_tunnel": False}, headers=H).json()

    wg0 = (env / "wireguard" / "wg0.conf").read_text()
    assert f"AllowedIPs = {r['ip']}/32, 192.168.88.0/24" in wg0
    groups = (env / "wireguard" / "wgp" / "tenants.list").read_text().splitlines()
    assert groups == ["10.252.1.0/24 192.168.88.0/24", "10.252.2.0/24"]

    # el móvil (split) del mismo cliente llega a la LAN; el de otro cliente no
    assert "AllowedIPs = 10.252.1.0/24, 10.252.0.1/32, 192.168.88.0/24" in admin.get(f"/api/devices/{phone['id']}/config").text
    assert "192.168.88.0/24" not in admin.get(f"/api/devices/{other['id']}/config").text
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in admin.get(f"/api/devices/{full['id']}/config").text
    # el router no enruta su propia LAN por el túnel ni cambia su DNS
    rconf = admin.get(f"/api/devices/{r['id']}/config").text
    assert "AllowedIPs = 10.252.1.0/24, 10.252.0.1/32\n" in rconf and "DNS =" not in rconf

    mt = admin.get(f"/api/devices/{r['id']}/mikrotik").text
    assert "/interface wireguard add name=wg-cloud" in mt
    assert "endpoint-address=203.0.113.10 endpoint-port=51820" in mt
    assert f"/ip address add address={r['ip']}/24 interface=wg-cloud" in mt
    assert "allowed-address=10.252.1.0/24,10.252.0.1/32 " in mt

    # router deshabilitado: su LAN sale del grupo y del wg0.conf
    admin.patch(f"/api/devices/{r['id']}", json={"enabled": False}, headers=H)
    assert (env / "wireguard" / "wgp" / "tenants.list").read_text().splitlines()[0] == "10.252.1.0/24"
    assert "192.168.88.0/24" not in admin.get(f"/api/devices/{phone['id']}/config").text

    # el DNS del cliente también atiende a los equipos de la LAN del router
    admin.patch(f"/api/devices/{r['id']}", json={"enabled": True}, headers=H)
    admin.post(f"/api/dns-zone/records?tenant_id={a['id']}", json={"name": "nas", "ip": "192.168.88.10"}, headers=H)
    dns = admin.app.state.dns
    assert dns.policy_for("192.168.88.25").tenant_id == a["id"]
    assert dns.policy_for("192.168.99.1") is None


def test_endpoint_setting(admin):
    a = mk(admin, "acme")
    d = admin.post("/api/devices", json={"name": "iPhone", "tenant_id": a["id"]}, headers=H).json()
    assert "Endpoint = 203.0.113.10:51820" in admin.get(f"/api/devices/{d['id']}/config").text
    assert admin.put("/api/admin/wg-settings", json={"endpoint": "no valido!"}, headers=H).status_code == 422
    r = admin.put("/api/admin/wg-settings", json={"endpoint": "WG.MiDominio.com"}, headers=H).json()
    assert r["effective"] == "wg.midominio.com"
    assert "Endpoint = wg.midominio.com:51820" in admin.get(f"/api/devices/{d['id']}/config").text
    assert admin.get("/api/admin/overview").json()["server"]["endpoint"] == "wg.midominio.com:51820"
    r = admin.put("/api/admin/wg-settings", json={"endpoint": ""}, headers=H).json()
    assert r["effective"] == "203.0.113.10"

from __future__ import annotations

import ipaddress

import pytest
from fastapi.testclient import TestClient

from app import wg
from app.config import load_settings
from app.main import create_app

H = {"X-WGP": "1"}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("WG_CONF_DIR", str(tmp_path / "wireguard"))
    monkeypatch.setenv("WG_ENDPOINT", "203.0.113.10")
    monkeypatch.setenv("SESSION_SECRET", "test-secret")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin")
    return tmp_path


@pytest.fixture()
def client(env):
    with TestClient(create_app()) as c:
        yield c


def login(c: TestClient, user: str, pw: str) -> dict:
    r = c.post("/api/auth/login", json={"username": user, "password": pw}, headers=H)
    assert r.status_code == 200, r.text
    return r.json()


def admin_ready(c: TestClient) -> None:
    assert login(c, "admin", "admin")["must_change"] is True
    r = c.post("/api/me/password", json={"current": "admin", "new": "SuperSecret1"}, headers=H)
    assert r.status_code == 200, r.text


def make_tenant(c: TestClient, username: str, **kw) -> dict:
    body = {"name": kw.pop("name", username.title()), "username": username, "password": "TenantPass1", **kw}
    r = c.post("/api/admin/tenants", json=body, headers=H)
    assert r.status_code == 201, r.text
    return r.json()


def test_csrf_header_required(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert r.status_code == 403


def test_must_change_blocks_api(client):
    login(client, "admin", "admin")
    assert client.get("/api/admin/tenants").status_code == 403
    assert client.get("/api/me").status_code == 200


def test_bad_login_and_rate_limit(client):
    for _ in range(10):
        assert client.post("/api/auth/login", json={"username": "admin", "password": "x"}, headers=H).status_code == 401
    assert client.post("/api/auth/login", json={"username": "admin", "password": "admin"}, headers=H).status_code == 429


def test_tenant_networks_and_device_flow(client, env):
    admin_ready(client)
    a = make_tenant(client, "acme")
    b = make_tenant(client, "globex", max_devices=1)
    assert a["network"] == "10.252.1.0/24"
    assert b["network"] == "10.252.2.0/24"

    r = client.post("/api/devices", json={"name": "Laptop", "tenant_id": a["id"]}, headers=H)
    assert r.status_code == 201
    dev = r.json()
    assert dev["ip"] == "10.252.1.2"

    # wg0.conf y lista de redes para el firewall del host
    conf = (env / "wireguard" / "wg0.conf").read_text()
    assert "AllowedIPs = 10.252.1.2/32" in conf
    assert "PostUp = /usr/local/sbin/wgp-firewall up %i" in conf
    nets = (env / "wireguard" / "wgp" / "tenants.list").read_text().split()
    assert nets == ["10.252.1.0/24", "10.252.2.0/24"]
    assert (env / "wireguard" / "wgp" / "apply.stamp").exists()

    # configuración de cliente y QR
    cfg = client.get(f"/api/devices/{dev['id']}/config").text
    assert "Address = 10.252.1.2/32" in cfg and "Endpoint = 203.0.113.10:51820" in cfg
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in cfg
    client.patch(f"/api/devices/{dev['id']}", json={"full_tunnel": False}, headers=H)
    cfg = client.get(f"/api/devices/{dev['id']}/config").text
    assert "AllowedIPs = 10.252.1.0/24" in cfg and "DNS" not in cfg
    qr = client.get(f"/api/devices/{dev['id']}/qr.svg")
    assert qr.status_code == 200 and qr.headers["content-type"].startswith("image/svg+xml")

    # límite de dispositivos
    assert client.post("/api/devices", json={"name": "p1", "tenant_id": b["id"]}, headers=H).status_code == 201
    assert client.post("/api/devices", json={"name": "p2", "tenant_id": b["id"]}, headers=H).status_code == 409

    # deshabilitar cliente: desaparece del wg0.conf y de la lista
    client.patch(f"/api/admin/tenants/{a['id']}", json={"enabled": False}, headers=H)
    assert "10.252.1.2/32" not in (env / "wireguard" / "wg0.conf").read_text()
    assert (env / "wireguard" / "wgp" / "tenants.list").read_text().split() == ["10.252.2.0/24"]

    # borrar cliente libera su red para el siguiente
    assert client.delete(f"/api/admin/tenants/{a['id']}", headers=H).status_code == 200
    c3 = make_tenant(client, "initech")
    assert c3["network"] == "10.252.1.0/24"


def test_tenant_isolation_in_api(client):
    admin_ready(client)
    a = make_tenant(client, "acme")
    b = make_tenant(client, "globex")
    da = client.post("/api/devices", json={"name": "a1", "tenant_id": a["id"]}, headers=H).json()
    client.post("/api/auth/logout", headers=H)

    # el cliente B entra, cambia su contraseña y sólo ve lo suyo
    assert login(client, "globex", "TenantPass1")["must_change"] is True
    assert client.get("/api/devices").status_code == 403
    client.post("/api/me/password", json={"current": "TenantPass1", "new": "GlobexPass2"}, headers=H)
    assert client.get("/api/devices").json() == []
    assert client.get(f"/api/devices/{da['id']}/config").status_code == 404
    assert client.delete(f"/api/devices/{da['id']}", headers=H).status_code == 404
    assert client.get("/api/admin/tenants").status_code == 403

    # crea en su propia red aunque intente forzar otro tenant_id
    r = client.post("/api/devices", json={"name": "b1", "tenant_id": a["id"]}, headers=H)
    assert r.status_code == 201 and r.json()["tenant_id"] == b["id"] and r.json()["ip"] == "10.252.2.2"
    me = client.get("/api/me").json()
    assert me["network"] == "10.252.2.0/24" and me["role"] == "tenant"


def test_disabled_tenant_cannot_login(client):
    admin_ready(client)
    a = make_tenant(client, "acme")
    client.patch(f"/api/admin/tenants/{a['id']}", json={"enabled": False}, headers=H)
    r = client.post("/api/auth/login", json={"username": "acme", "password": "TenantPass1"}, headers=H)
    assert r.status_code == 403


def test_password_change_invalidates_old_session(env):
    app = create_app()
    with TestClient(app) as c1, TestClient(app) as c2:
        admin_ready(c1)
        login(c2, "admin", "SuperSecret1")
        assert c2.get("/api/admin/tenants").status_code == 200
        c1.post("/api/me/password", json={"current": "SuperSecret1", "new": "OtherSecret2"}, headers=H)
        assert c2.get("/api/admin/tenants").status_code == 401
        assert c1.get("/api/admin/tenants").status_code == 200


def test_username_unique_across_roles(client):
    admin_ready(client)
    r = client.post("/api/admin/tenants", json={"name": "x", "username": "ADMIN", "password": "TenantPass1"}, headers=H)
    assert r.status_code == 409


def test_address_math(env):
    s = load_settings()
    assert s.tenant_capacity == 255
    assert wg.tenant_network(s, 255) == ipaddress.ip_network("10.252.255.0/24")
    assert wg.device_capacity(s) == 253
    with pytest.raises(ValueError):
        wg.tenant_network(s, 0)


def test_keys_are_valid_curve25519(env):
    priv, pub = wg.generate_keypair()
    import base64
    assert len(base64.b64decode(priv)) == 32 and len(base64.b64decode(pub)) == 32


def test_pwa_assets(client):
    m = client.get("/manifest.webmanifest")
    assert m.status_code == 200 and m.headers["content-type"].startswith("application/manifest+json")
    data = m.json()
    assert data["display"] == "standalone"
    assert any(i["purpose"] == "maskable" for i in data["icons"])
    for icon in data["icons"]:
        assert client.get(icon["src"]).status_code == 200
    sw = client.get("/sw.js")
    assert sw.status_code == 200 and "javascript" in sw.headers["content-type"]
    assert "__VERSION__" not in sw.text and "wgp-" in sw.text
    assert sw.headers["service-worker-allowed"] == "/"
    html = client.get("/").text
    assert 'user-scalable=no' in html and 'rel="manifest"' in html and "apple-touch-icon" in html

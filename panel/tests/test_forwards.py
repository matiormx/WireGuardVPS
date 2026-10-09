from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

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
    monkeypatch.setenv("RESERVED_PORTS", "22 2222 51820 5000")
    monkeypatch.setattr("app.wg.WireGuardManager.host_networks", lambda self: [])
    with TestClient(create_app()) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": "admin"}, headers=H)
        c.post("/api/me/password", json={"current": "admin", "new": "AdminPass1"}, headers=H)
        c.fw_list = tmp_path / "wireguard" / "wgp" / "forwards.list"
        yield c


def mk(c, username):
    return c.post("/api/admin/tenants", json={"name": username.title(), "username": username, "password": "Password1"},
                  headers=H).json()


def fwd(c, tid, port, ip, tport=80, proto="tcp", **kw):
    return c.post("/api/forwards", json={"proto": proto, "public_port": port, "target_ip": ip, "target_port": tport,
                                         "tenant_id": tid, **kw}, headers=H)


def tenant_client(admin, username, tid):
    admin.patch(f"/api/admin/tenants/{tid}", json={"password": "Temporal1"}, headers=H)
    c = TestClient(admin.app)
    c.post("/api/auth/login", json={"username": username, "password": "Temporal1"}, headers=H)
    c.post("/api/me/password", json={"current": "Temporal1", "new": "Cliente222"}, headers=H)
    return c


def test_forwards_lifecycle(admin):
    a, b = mk(admin, "acme"), mk(admin, "globex")
    admin.post("/api/devices", json={"name": "MikroTik", "tenant_id": a["id"], "kind": "router",
                                     "lan_networks": ["192.168.88.0/24"]}, headers=H)
    r = fwd(admin, a["id"], 8443, "10.252.1.50", 443, description="NAS")
    assert r.status_code == 201 and r.json()["proto"] == "tcp"
    assert fwd(admin, a["id"], 3389, "192.168.88.20", 3389, proto="both").status_code == 201  # LAN del router
    assert fwd(admin, a["id"], 9000, "10.252.2.5").status_code == 422     # red de otro cliente
    assert fwd(admin, a["id"], 9000, "8.8.8.8").status_code == 422        # fuera de su red
    for port in (22, 2222, 53, 80, 443, 51820, 5000, 2019):               # puertos del servidor
        assert fwd(admin, a["id"], port, "10.252.1.50").status_code == 409, port
    assert fwd(admin, b["id"], 8443, "10.252.2.5", proto="udp").status_code == 201  # mismo puerto, otro protocolo
    assert fwd(admin, b["id"], 8443, "10.252.2.5").status_code == 409                 # TCP ya ocupado
    assert fwd(admin, b["id"], 3389, "10.252.2.5", proto="udp").status_code == 409    # «both» ocupa los dos

    assert admin.fw_list.read_text().splitlines() == [
        "tcp 3389 192.168.88.20 3389", "udp 3389 192.168.88.20 3389",
        "tcp 8443 10.252.1.50 443", "udp 8443 10.252.2.5 80",
    ]
    data = admin.get(f"/api/forwards?tenant_id={a['id']}").json()
    assert data["max"] == 5 and data["public_host"] == "203.0.113.10" and len(data["forwards"]) == 2
    assert data["networks"] == ["10.252.1.0/24", "192.168.88.0/24"]
    assert 20000 <= data["suggested_port"] <= 29999

    # Pausar, editar y suspender al cliente retira las reglas
    fid = r.json()["id"]
    admin.patch(f"/api/forwards/{fid}", json={"enabled": False}, headers=H)
    assert "tcp 8443 10.252.1.50 443" not in admin.fw_list.read_text()
    admin.patch(f"/api/forwards/{fid}", json={"enabled": True, "target_port": 5001}, headers=H)
    assert "tcp 8443 10.252.1.50 5001" in admin.fw_list.read_text()
    admin.patch(f"/api/admin/tenants/{a['id']}", json={"enabled": False}, headers=H)
    assert admin.fw_list.read_text() == "udp 8443 10.252.2.5 80\n"
    admin.patch(f"/api/admin/tenants/{a['id']}", json={"enabled": True}, headers=H)
    admin.delete(f"/api/admin/tenants/{b['id']}", headers=H)
    assert "10.252.2.5" not in admin.fw_list.read_text()


def test_tenant_limits_and_isolation(admin):
    a, b = mk(admin, "acme"), mk(admin, "globex")
    ca = tenant_client(admin, "acme", a["id"])
    assert ca.post("/api/forwards", json={"public_port": 80, "target_ip": "10.252.1.9", "target_port": 80},
                   headers=H).status_code == 409                          # reservado
    assert ca.post("/api/forwards", json={"public_port": 1000, "target_ip": "10.252.1.9", "target_port": 80},
                   headers=H).status_code == 422                          # < 1024 sólo admin
    ok = ca.post("/api/forwards", json={"public_port": 20001, "target_ip": "10.252.1.9", "target_port": 80,
                                        "tenant_id": b["id"]}, headers=H)  # tenant_id ajeno se ignora
    assert ok.status_code == 201 and ok.json()["tenant_id"] == a["id"]
    admin.patch(f"/api/admin/tenants/{a['id']}", json={"max_forwards": 1}, headers=H)
    assert ca.post("/api/forwards", json={"public_port": 20002, "target_ip": "10.252.1.9", "target_port": 80},
                   headers=H).status_code == 409
    cb = tenant_client(admin, "globex", b["id"])
    fid = ok.json()["id"]
    assert cb.get(f"/api/forwards?tenant_id={a['id']}").json()["forwards"] == []
    assert cb.patch(f"/api/forwards/{fid}", json={"enabled": False}, headers=H).status_code == 404
    assert cb.delete(f"/api/forwards/{fid}", headers=H).status_code == 404
    assert cb.get(f"/api/forwards/{fid}/status").status_code == 404
    assert "ok" in ca.get(f"/api/forwards/{fid}/status").json()["target"]
    assert ca.delete(f"/api/forwards/{fid}", headers=H).status_code == 200

from __future__ import annotations

import time

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
    monkeypatch.setattr("app.wg.WireGuardManager.host_networks", lambda self: [])
    with TestClient(create_app()) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": "admin"}, headers=H)
        c.post("/api/me/password", json={"current": "admin", "new": "AdminPass1"}, headers=H)
        yield c


def login(app, username, password, new=None):
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"username": username, "password": password}, headers=H)
    assert r.status_code == 200, r.text
    if new:
        c.post("/api/me/password", json={"current": password, "new": new}, headers=H)
    return c


def setup(admin):
    t = admin.post("/api/admin/tenants", json={"name": "Acme", "username": "acme", "password": "Temporal1"}, headers=H).json()
    other = admin.post("/api/admin/tenants", json={"name": "Globex", "username": "globex", "password": "Temporal1"}, headers=H).json()
    boss = login(admin.app, "acme", "Temporal1", "Responsable1")
    return t, other, boss


def test_members_invites_and_permissions(admin):
    t, other, boss = setup(admin)
    # Alta directa con contraseña temporal
    m = boss.post("/api/members", json={"name": "Ana López", "username": "ana", "password": "Temporal2"}, headers=H)
    assert m.status_code == 201 and m.json()["must_change"]
    assert boss.post("/api/members", json={"name": "X", "username": "acme", "password": "Temporal2"}, headers=H).status_code == 409
    assert boss.post("/api/members", json={"name": "X", "username": "admin", "password": "Temporal2"}, headers=H).status_code == 409

    # Invitación: enlace de un solo uso
    inv = boss.post("/api/members/invite", json={"name": "Pablo", "can_create": False}, headers=H).json()
    token = inv["url"].split("/#/invite/")[1]
    anon = TestClient(admin.app)
    assert anon.get(f"/api/invite/{token}").json()["tenant"] == "Acme"
    assert anon.get("/api/invite/falso").status_code == 404
    assert anon.post(f"/api/invite/{token}", json={"username": "ana", "password": "Clave1234"}, headers=H).status_code == 409
    r = anon.post(f"/api/invite/{token}", json={"username": "pablo", "password": "Clave1234"}, headers=H)
    assert r.status_code == 200 and anon.get("/api/me").json()["role"] == "member"
    assert anon.get("/api/me").json()["tenant_name"] == "Acme" and anon.get("/api/me").json()["can_create"] is False
    assert TestClient(admin.app).get(f"/api/invite/{token}").status_code == 404  # ya usada
    pablo = anon

    ana = login(admin.app, "ana", "Temporal2")
    assert ana.get("/api/devices").status_code == 403  # debe cambiar la contraseña antes
    ana.post("/api/me/password", json={"current": "Temporal2", "new": "AnaClave99"}, headers=H)

    # El responsable crea dispositivos y los asigna; los usuarios sólo ven los suyos
    ana_id = m.json()["id"]
    d1 = boss.post("/api/devices", json={"name": "Portátil Ana", "member_id": ana_id}, headers=H).json()
    d2 = boss.post("/api/devices", json={"name": "Servidor"}, headers=H).json()
    assert d1["member_id"] == ana_id and d1["member_name"] == "Ana López"
    foreign = admin.post("/api/admin/tenants", json={"name": "Z", "username": "zeta", "password": "Temporal1"}, headers=H).json()
    zm = admin.post("/api/members", json={"name": "Z", "username": "zmember", "password": "Temporal2", "tenant_id": foreign["id"]},
                    headers=H).json()
    assert boss.post("/api/devices", json={"name": "X", "member_id": zm["id"]}, headers=H).status_code == 422

    assert [d["name"] for d in ana.get("/api/devices").json()] == ["Portátil Ana"]
    assert ana.get(f"/api/devices/{d2['id']}/config").status_code == 404
    assert ana.get(f"/api/devices/{d1['id']}/config").status_code == 200
    assert ana.get(f"/api/devices/{d1['id']}/qr.svg").status_code == 200
    assert ana.patch(f"/api/devices/{d1['id']}", json={"name": "Mi portátil", "monitor": True}, headers=H).status_code == 200
    assert ana.patch(f"/api/devices/{d1['id']}", json={"dns_filter": False}, headers=H).status_code == 403
    assert ana.patch(f"/api/devices/{d1['id']}", json={"member_id": 0}, headers=H).status_code == 403
    assert ana.patch(f"/api/devices/{d2['id']}", json={"name": "x"}, headers=H).status_code == 404
    own = ana.post("/api/devices", json={"name": "Móvil Ana", "tenant_id": other["id"]}, headers=H).json()
    assert own["tenant_id"] == t["id"] and own["member_id"] == ana_id   # siempre en su cliente, a su nombre
    assert ana.post("/api/devices", json={"name": "R", "kind": "router", "lan_networks": ["192.168.50.0/24"]}, headers=H).status_code == 403
    assert pablo.post("/api/devices", json={"name": "Móvil Pablo"}, headers=H).status_code == 403  # sin permiso de alta

    # Lo que es del responsable queda fuera de su alcance
    for path in ("/api/members", "/api/forwards", "/api/services", "/api/dns-zone", "/api/filters", "/api/history/dns"):
        assert ana.get(path).status_code == 403, path
    assert ana.post("/api/members/invite", json={"name": "x"}, headers=H).status_code == 403
    tr = ana.get("/api/history/traffic").json()
    assert tr["scope"]["tenant"] == "Acme"
    assert ana.get(f"/api/history/traffic?device_id={d2['id']}").status_code == 404
    assert ana.get(f"/api/history/events?device_id={d1['id']}").status_code == 200

    # Gestión: desactivar, restablecer, eliminar
    lst = boss.get("/api/members").json()
    assert {x["username"] for x in lst["members"]} == {"ana", "pablo"} and lst["invites"] == []
    assert next(x for x in lst["members"] if x["username"] == "ana")["devices"] == 2
    assert admin.get(f"/api/members?tenant_id={other['id']}").json()["members"] == []
    other_boss = login(admin.app, "globex", "Temporal1", "Globex2222")
    assert other_boss.patch(f"/api/members/{ana_id}", json={"enabled": False}, headers=H).status_code == 404
    boss.patch(f"/api/members/{ana_id}", json={"enabled": False}, headers=H)
    assert ana.get("/api/devices").status_code == 401
    assert TestClient(admin.app).post("/api/auth/login", json={"username": "ana", "password": "AnaClave99"}, headers=H).status_code == 403
    boss.patch(f"/api/members/{ana_id}", json={"enabled": True, "password": "Nueva1234"}, headers=H)
    ana = login(admin.app, "ana", "Nueva1234")
    assert ana.get("/api/me").json()["must_change"] is True
    boss.delete(f"/api/members/{ana_id}", headers=H)
    devs = {d["name"]: d for d in boss.get("/api/devices").json()}
    assert devs["Mi portátil"]["member_id"] is None  # el dispositivo se queda en el cliente
    # Suspender al cliente deja fuera también a sus usuarios
    admin.patch(f"/api/admin/tenants/{t['id']}", json={"enabled": False}, headers=H)
    assert pablo.get("/api/me").status_code == 401


def test_install_links(admin):
    t, _, boss = setup(admin)
    d = boss.post("/api/devices", json={"name": "iPhone de Pablo"}, headers=H).json()
    assert boss.post(f"/api/devices/{d['id']}/link", json={"hours": 5}, headers=H).status_code == 422
    link = boss.post(f"/api/devices/{d['id']}/link", json={"hours": 24}, headers=H).json()
    assert link["active"] and link["expires_at"] > time.time() + 23 * 3600
    token = link["url"].split("/#/get/")[1]
    anon = TestClient(admin.app)
    got = anon.get(f"/api/get/{token}").json()
    assert got["device"] == "iPhone de Pablo" and "[Interface]" in got["conf"] and got["filename"].endswith(".conf")
    assert anon.get(f"/api/get/{token}/qr.svg").headers["content-type"].startswith("image/svg")
    assert boss.get(f"/api/devices/{d['id']}/link").json()["views"] == 1
    # Uno nuevo invalida el anterior; revocar lo invalida
    link2 = boss.post(f"/api/devices/{d['id']}/link", json={"hours": 1}, headers=H).json()
    assert anon.get(f"/api/get/{token}").status_code == 404
    token2 = link2["url"].split("/#/get/")[1]
    boss.patch(f"/api/devices/{d['id']}", json={"enabled": False}, headers=H)
    assert anon.get(f"/api/get/{token2}").status_code == 404   # dispositivo deshabilitado
    boss.patch(f"/api/devices/{d['id']}", json={"enabled": True}, headers=H)
    assert anon.get(f"/api/get/{token2}").status_code == 200
    boss.delete(f"/api/devices/{d['id']}/link", headers=H)
    assert anon.get(f"/api/get/{token2}").status_code == 404
    other = login(admin.app, "globex", "Temporal1", "Globex2222")
    assert other.post(f"/api/devices/{d['id']}/link", json={"hours": 1}, headers=H).status_code == 404

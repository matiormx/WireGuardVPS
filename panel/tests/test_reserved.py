from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import domains, reserved
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
    monkeypatch.setattr(domains.Domains, "resolve", staticmethod(lambda host: ["203.0.113.10"]))
    with TestClient(create_app()) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": "admin"}, headers=H)
        c.post("/api/me/password", json={"current": "admin", "new": "AdminPass1"}, headers=H)
        yield c


def new_tenant(c, username):
    return c.post("/api/admin/tenants", json={"name": "X", "username": username, "password": "Password1"}, headers=H)


def test_normalize():
    assert reserved.normalize("Ad_Min") == "admin" and reserved.normalize("SOPORTE-") == "soporte"
    assert "www" in reserved.DEFAULT_WORDS and "admin" in reserved.DEFAULT_WORDS


def test_reserved_usernames(admin):
    for name in ("www", "Soporte", "ad_min", "root", "no.reply"):
        r = new_tenant(admin, name)
        assert r.status_code == 422 and "reservado" in r.json()["detail"], name
    assert new_tenant(admin, "acme").status_code == 201
    t = admin.get("/api/admin/tenants").json()[0]
    # usuarios dentro de un cliente
    r = admin.post("/api/members", json={"tenant_id": t["id"], "name": "Ana", "username": "Soporte", "password": "Password1"}, headers=H)
    assert r.status_code == 422
    assert admin.post("/api/members", json={"tenant_id": t["id"], "name": "Ana", "username": "ana", "password": "Password1"},
                      headers=H).status_code == 201


def test_edit_list(admin):
    st = admin.get("/api/admin/reserved").json()
    assert st["default"] and "www" in st["words"] and st["count"] == len(reserved.DEFAULT_WORDS)
    assert admin.put("/api/admin/reserved", json={"words": ["mal palabra"]}, headers=H).status_code == 422
    st = admin.put("/api/admin/reserved", json={"words": ["MiMarca", "competencia", "www", "www"]}, headers=H).json()
    assert st["words"] == ["competencia", "mimarca", "www"] and not st["default"]
    assert new_tenant(admin, "mi_marca").status_code == 422          # normalizado
    assert new_tenant(admin, "admin2").status_code == 201             # ya no está en la lista
    st = admin.delete("/api/admin/reserved", headers=H).json()
    assert st["default"] and "admin" in st["words"]
    # sólo el administrador
    admin.post("/api/auth/logout", headers=H)
    admin.post("/api/auth/login", json={"username": "admin2", "password": "Password1"}, headers=H)
    assert admin.get("/api/admin/reserved").status_code == 403

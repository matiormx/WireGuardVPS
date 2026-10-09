from __future__ import annotations

import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from app import domains
from app.main import create_app

H = {"X-WGP": "1"}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("WG_CONF_DIR", str(tmp_path / "wireguard"))
    monkeypatch.setenv("WG_ENDPOINT", "203.0.113.10")
    monkeypatch.setenv("SESSION_SECRET", "x")
    monkeypatch.setenv("DNS_ENABLED", "false")
    # DNS simulado: los dominios *.ok.test apuntan al servidor, el resto a otra IP.
    monkeypatch.setattr(domains.Domains, "resolve",
                        staticmethod(lambda host: ["203.0.113.10"] if host.endswith("ok.test") else ["198.51.100.7"]))
    state = {"https": False}
    monkeypatch.setattr(domains.Domains, "https_status",
                        staticmethod(lambda host: {"ok": state["https"], "error": None if state["https"] else "sin certificado"}))
    return state


@pytest.fixture()
def admin(env):
    with TestClient(create_app()) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": "admin"}, headers=H)
        c.post("/api/me/password", json={"current": "admin", "new": "AdminPass1"}, headers=H)
        yield c


def tenant(c, username):
    r = c.post("/api/admin/tenants", json={"name": username.title(), "username": username, "password": "Password1"}, headers=H)
    return r.json()


def test_normalize_host():
    assert domains.normalize_host(" HTTPS://Vpn.MiEmpresa.com/login ") == "vpn.miempresa.com"
    assert domains.normalize_host("panel.ejemplo.es.") == "panel.ejemplo.es"
    for bad in ("1.2.3.4", "localhost", "a b.com", "-x.com", "x", "", None, "ejemplo.123"):
        assert domains.normalize_host(bad) is None
    assert domains.host_of("vpn.a.com:5000") == "vpn.a.com"


def test_main_domain_and_force_https(admin, env):
    r = admin.put("/api/admin/settings", json={"main_domain": "no valido"}, headers=H)
    assert r.status_code == 422
    r = admin.put("/api/admin/settings", json={"main_domain": "Panel.ok.test", "force_https": False}, headers=H)
    assert r.status_code == 200 and r.json()["main_domain"] == "panel.ok.test"
    assert r.json()["server_ips"] == ["203.0.113.10"]

    st = admin.get("/api/domain-status?target=main").json()
    assert st["dns"]["ok"] and not st["https"]["ok"]

    # No se puede forzar HTTPS si aún no funciona (evita dejar el panel inaccesible).
    r = admin.put("/api/admin/settings", json={"main_domain": "panel.ok.test", "force_https": True}, headers=H)
    assert r.status_code == 409
    env["https"] = True
    r = admin.put("/api/admin/settings", json={"main_domain": "panel.ok.test", "force_https": True}, headers=H)
    assert r.status_code == 200 and r.json()["force_https"] is True

    # Acceso directo por HTTP -> redirección permanente al dominio con HTTPS
    r = admin.get("/api/me?x=1", follow_redirects=False)
    assert r.status_code == 308 and r.headers["location"] == "https://panel.ok.test/api/me?x=1"


def test_tenant_domains(admin, env):
    a = tenant(admin, "acme")
    b = tenant(admin, "globex")
    admin.put("/api/admin/settings", json={"main_domain": "panel.ok.test"}, headers=H)

    r = admin.put(f"/api/tenant-domain?tenant_id={a['id']}", json={"domain": "vpn.acme.ok.test"}, headers=H)
    assert r.status_code == 200 and r.json()["domain"] == "vpn.acme.ok.test"
    assert admin.put(f"/api/tenant-domain?tenant_id={b['id']}", json={"domain": "VPN.acme.ok.test"}, headers=H).status_code == 409
    assert admin.put(f"/api/tenant-domain?tenant_id={b['id']}", json={"domain": "panel.ok.test"}, headers=H).status_code == 409
    assert admin.put("/api/admin/settings", json={"main_domain": "vpn.acme.ok.test"}, headers=H).status_code == 409
    assert admin.put("/api/tenant-domain", json={"domain": "x.ok.test"}, headers=H).status_code == 400  # admin sin tenant_id

    listed = admin.get("/api/admin/settings").json()["tenant_domains"]
    assert listed == [{"tenant_id": a["id"], "name": "Acme", "domain": "vpn.acme.ok.test", "enabled": True}]

    # Marca y manifest según el dominio
    host = {"Host": "vpn.acme.ok.test"}
    assert admin.get("/api/branding", headers=host).json() == {"title": "Acme", "tenant": True}
    assert admin.get("/api/branding").json()["tenant"] is False
    assert admin.get("/manifest.webmanifest", headers=host).json()["name"] == "Acme"

    # En el dominio de Acme sólo entra Acme
    with TestClient(admin.app) as c2:
        r = c2.post("/api/auth/login", json={"username": "admin", "password": "AdminPass1"}, headers={**H, **host})
        assert r.status_code == 403
        r = c2.post("/api/auth/login", json={"username": "globex", "password": "Password1"}, headers={**H, **host})
        assert r.status_code == 403
        r = c2.post("/api/auth/login", json={"username": "acme", "password": "Password1"}, headers={**H, **host})
        assert r.status_code == 200
        # El cliente gestiona su propio dominio (y no puede tocar el de otro)
        c2.post("/api/me/password", json={"current": "Password1", "new": "AcmePass22"}, headers={**H, **host})
        mine = c2.get(f"/api/tenant-domain?tenant_id={b['id']}", headers=host).json()
        assert mine["tenant_id"] == a["id"] and mine["domain"] == "vpn.acme.ok.test"
        st = c2.get("/api/domain-status", headers=host).json()
        assert st["domain"] == "vpn.acme.ok.test" and st["dns"]["ok"]
        assert c2.get("/api/domain-status?target=main", headers=host).status_code == 403
        r = c2.put("/api/tenant-domain", json={"domain": None}, headers={**H, **host})
        assert r.status_code == 200 and r.json()["domain"] is None


def test_tls_ask(admin, env):
    a = tenant(admin, "acme")
    admin.put(f"/api/tenant-domain?tenant_id={a['id']}", json={"domain": "vpn.acme.ok.test"}, headers=H)
    admin.put("/api/admin/settings", json={"main_domain": "panel.ok.test"}, headers=H)
    b = tenant(admin, "evil")
    admin.put(f"/api/tenant-domain?tenant_id={b['id']}", json={"domain": "google.com"}, headers=H)  # DNS no apunta aquí

    # Desde fuera (no localhost) el endpoint no existe
    assert admin.get("/internal/tls-ask?domain=panel.ok.test").status_code == 404

    async def ask(domain, headers=None):
        transport = httpx.ASGITransport(app=admin.app, client=("127.0.0.1", 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:5000") as c:
            return (await c.get(f"/internal/tls-ask?domain={domain}", headers=headers or {})).status_code

    assert asyncio.run(ask("panel.ok.test")) == 200
    assert asyncio.run(ask("vpn.acme.ok.test")) == 200
    assert asyncio.run(ask("google.com")) == 404          # dado de alta pero el DNS no es nuestro
    assert asyncio.run(ask("otro.ok.test")) == 404        # no dado de alta
    # A través de Caddy (lleva X-Forwarded-For) tampoco se puede consultar
    assert asyncio.run(ask("panel.ok.test", {"X-Forwarded-For": "1.2.3.4"})) == 404
    # Cliente suspendido: su dominio deja de autorizarse
    admin.patch(f"/api/admin/tenants/{a['id']}", json={"enabled": False}, headers=H)
    assert asyncio.run(ask("vpn.acme.ok.test")) == 404

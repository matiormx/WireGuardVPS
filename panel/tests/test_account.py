from __future__ import annotations

import re

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
    monkeypatch.setenv("CADDY_ADMIN", "")
    monkeypatch.setattr("app.wg.WireGuardManager.host_networks", lambda self: [])
    monkeypatch.setattr(domains.Domains, "resolve", staticmethod(lambda host: ["203.0.113.10"]))
    with TestClient(create_app()) as c:
        sent = []
        monkeypatch.setattr(c.app.state.notifier, "email", lambda to, subject, body: sent.append((to, subject, body)))
        c.post("/api/auth/login", json={"username": "admin", "password": "admin"}, headers=H)
        c.post("/api/me/password", json={"current": "admin", "new": "AdminPass1"}, headers=H)
        c.post("/api/admin/tenants", json={"name": "Acme", "username": "acme", "password": "Password1"}, headers=H)
        c.post("/api/auth/logout", headers=H)
        yield c, sent


def code_of(msg):
    return re.search(r"\b(\d{6})\b", msg[2]).group(1)


def login(c, user, pw):
    return c.post("/api/auth/login", json={"username": user, "password": pw}, headers=H)


def enable_email(c):
    c.post("/api/auth/login", json={"username": "admin", "password": "AdminPass1"}, headers=H)
    c.put("/api/admin/alerts-config", json={"smtp_host": "smtp.ejemplo.com", "smtp_from": "avisos@ejemplo.com"}, headers=H)
    c.post("/api/auth/logout", headers=H)


def setup_tenant(c, sent):
    login(c, "acme", "Password1")
    c.post("/api/me/password", json={"current": "Password1", "new": "Password22"}, headers=H)
    assert c.post("/api/me/email", json={"email": "Ana@Acme.com", "password": "mal"}, headers=H).status_code == 400
    st = c.post("/api/me/email", json={"email": "Ana@Acme.com", "password": "Password22"}, headers=H).json()
    assert st["pending"] == "ana@acme.com" and st["email"] is None
    assert sent[-1][0] == "ana@acme.com"
    assert c.post("/api/me/email/verify", json={"code": "000000" if code_of(sent[-1]) != "000000" else "111111"}, headers=H).status_code == 400
    st = c.post("/api/me/email/verify", json={"code": code_of(sent[-1])}, headers=H).json()
    assert st["email"] == "ana@acme.com" and st["verified"] and not st["twofa"]


def test_email_requires_server_email(env):
    c, sent = env
    login(c, "acme", "Password1")
    c.post("/api/me/password", json={"current": "Password1", "new": "Password22"}, headers=H)
    assert c.get("/api/me/security").json()["email_available"] is False
    assert c.post("/api/me/email", json={"email": "ana@acme.com", "password": "Password22"}, headers=H).status_code == 409
    assert c.get("/api/auth/forgot").json() == {"enabled": False}


def test_two_factor_login(env):
    c, sent = env
    enable_email(c)
    setup_tenant(c, sent)
    assert c.put("/api/me/2fa", json={"enabled": True, "password": "mal"}, headers=H).status_code == 400
    assert c.put("/api/me/2fa", json={"enabled": True, "password": "Password22"}, headers=H).json()["twofa"] is True
    c.post("/api/auth/logout", headers=H)
    # contraseña correcta -> no hay sesión hasta el código
    r = login(c, "acme", "Password22").json()
    assert r["twofa"] and r["email"] == "a••@a•••.com" and "role" not in r
    assert c.get("/api/me").status_code == 401
    ch = r["challenge"]
    assert c.post("/api/auth/2fa", json={"challenge": ch, "code": "12345x"}, headers=H).status_code == 400
    assert c.post("/api/auth/2fa/resend", json={"challenge": ch}, headers=H).status_code == 429   # demasiado pronto
    assert c.post("/api/auth/2fa", json={"challenge": "x" * 20, "code": code_of(sent[-1])}, headers=H).status_code == 410
    r = c.post("/api/auth/2fa", json={"challenge": ch, "code": code_of(sent[-1])}, headers=H)
    assert r.status_code == 200 and r.json()["role"] == "tenant" and c.get("/api/me").json()["username"] == "acme"
    # el código no sirve dos veces
    assert c.post("/api/auth/2fa", json={"challenge": ch, "code": code_of(sent[-1])}, headers=H).status_code == 410
    # 5 fallos invalidan el reto
    c.post("/api/auth/logout", headers=H)
    ch = login(c, "acme", "Password22").json()["challenge"]
    good = code_of(sent[-1])
    for _ in range(5):
        c.post("/api/auth/2fa", json={"challenge": ch, "code": "999999" if good != "999999" else "888888"}, headers=H)
    assert c.post("/api/auth/2fa", json={"challenge": ch, "code": good}, headers=H).status_code in (410, 429)
    # desactivar quita el paso (con la contraseña)
    c.post("/api/auth/login", json={"username": "acme", "password": "Password22"}, headers=H)


def test_password_reset(env):
    c, sent = env
    enable_email(c)
    setup_tenant(c, sent)
    c.post("/api/auth/logout", headers=H)
    assert c.get("/api/auth/forgot").json() == {"enabled": True}
    n = len(sent)
    # respuesta idéntica exista o no la cuenta / el email
    for who in ("nadie", "nadie@x.com", "admin"):          # admin no tiene email verificado
        assert c.post("/api/auth/forgot", json={"login": who}, headers=H).json() == {"ok": True}
    assert len(sent) == n
    assert c.post("/api/auth/forgot", json={"login": "ANA@acme.com"}, headers={**H, "Host": "evil.example"}).json() == {"ok": True}
    to, subject, body = sent[-1]
    assert to == "ana@acme.com" and "acme" in body and "evil.example" not in body and "203.0.113.10" in body
    token = re.search(r"#/reset\?token=([\w-]+)", body).group(1)
    assert c.post("/api/auth/forgot", json={"login": "acme"}, headers=H).json() == {"ok": True}
    assert len(sent) == n + 1                               # no se reenvía enseguida
    assert c.post("/api/auth/reset", json={"token": "x" * 20, "password": "Nueva12345"}, headers=H).status_code == 400
    assert c.post("/api/auth/reset", json={"token": token, "password": "corta"}, headers=H).status_code == 422
    r = c.post("/api/auth/reset", json={"token": token, "password": "Nueva12345"}, headers=H).json()
    assert r == {"ok": True, "username": "acme"}
    assert c.post("/api/auth/reset", json={"token": token, "password": "Otra123456"}, headers=H).status_code == 400   # un solo uso
    assert login(c, "acme", "Password22").status_code == 401 and login(c, "acme", "Nueva12345").status_code == 200


def test_reset_link_uses_known_domain(env):
    c, sent = env
    enable_email(c)
    c.post("/api/auth/login", json={"username": "admin", "password": "AdminPass1"}, headers=H)
    c.put("/api/admin/settings", json={"main_domain": "vpn.ejemplo.com"}, headers=H)
    c.post("/api/auth/logout", headers=H)
    setup_tenant(c, sent)
    c.post("/api/auth/logout", headers=H)
    c.post("/api/auth/forgot", json={"login": "acme"}, headers={**H, "Host": "evil.example"})
    assert "https://vpn.ejemplo.com/#/reset?token=" in sent[-1][2]


def test_deleted_account_does_not_leak(env):
    c, sent = env
    enable_email(c)
    setup_tenant(c, sent)
    tid = c.get("/api/me").json()["id"]
    c.post("/api/auth/logout", headers=H)
    c.post("/api/auth/login", json={"username": "admin", "password": "AdminPass1"}, headers=H)
    c.delete(f"/api/admin/tenants/{tid}", headers=H)
    with c.app.state.db.conn() as db:
        assert db.execute("SELECT COUNT(*) FROM account_security").fetchone()[0] == 0

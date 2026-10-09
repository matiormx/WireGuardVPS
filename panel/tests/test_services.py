from __future__ import annotations

import http.server
import ipaddress
import threading
import time

import bcrypt
import pytest
from fastapi.testclient import TestClient

from app import caddy, domains
from app.main import create_app

H = {"X-WGP": "1"}


class FakeCaddyAdmin(http.server.BaseHTTPRequestHandler):
    loads: list = []

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        FakeCaddyAdmin.loads.append((self.path, self.headers["Content-Type"], body))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture()
def fake_caddy():
    FakeCaddyAdmin.loads = []
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeCaddyAdmin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()


@pytest.fixture()
def admin(tmp_path, monkeypatch, fake_caddy):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("WG_CONF_DIR", str(tmp_path / "wireguard"))
    monkeypatch.setenv("WG_ENDPOINT", "203.0.113.10")
    monkeypatch.setenv("SESSION_SECRET", "x")
    monkeypatch.setenv("DNS_ENABLED", "false")
    monkeypatch.setenv("CADDY_ADMIN", f"http://127.0.0.1:{fake_caddy.server_port}")
    monkeypatch.setenv("ACME_EMAIL", "admin@example.com")
    monkeypatch.setattr("app.wg.WireGuardManager.host_networks", lambda self: [])
    monkeypatch.setattr(domains.Domains, "resolve",
                        staticmethod(lambda host: ["203.0.113.10"] if host.endswith("ok.test") else ["198.51.100.7"]))
    with TestClient(create_app()) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": "admin"}, headers=H)
        c.post("/api/me/password", json={"current": "admin", "new": "AdminPass1"}, headers=H)
        yield c


def mk(c, username):
    return c.post("/api/admin/tenants", json={"name": username.title(), "username": username, "password": "Password1"}, headers=H).json()


def svc(c, tid, host, ip, port=5000, **kw):
    return c.post("/api/services", json={"hostname": host, "target_ip": ip, "target_port": port, "tenant_id": tid, **kw}, headers=H)


def last_caddyfile(check=lambda cf: True, timeout=4.0):
    """Última configuración enviada a Caddy, esperando a que cumpla `check`."""
    end = time.time() + timeout
    while True:
        if FakeCaddyAdmin.loads:
            path, ctype, body = FakeCaddyAdmin.loads[-1]
            assert path == "/load" and ctype == "text/caddyfile"
            if check(body) or time.time() > end:
                return body
        elif time.time() > end:
            raise AssertionError("Caddy no recibió configuración")
        time.sleep(0.05)


def test_validation_and_names(admin):
    a, b = mk(admin, "acme"), mk(admin, "globex")
    admin.post("/api/devices", json={"name": "MikroTik", "tenant_id": a["id"], "kind": "router",
                                     "lan_networks": ["192.168.88.0/24"]}, headers=H)
    assert svc(admin, a["id"], "nas.acme.ok.test", "10.252.2.5").status_code == 422      # red de otro cliente
    assert svc(admin, a["id"], "nas.acme.ok.test", "8.8.8.8").status_code == 422         # fuera de su red
    assert svc(admin, a["id"], "1.2.3.4", "10.252.1.50").status_code == 422              # nombre no válido
    r = svc(admin, a["id"], "NAS.acme.ok.test", "10.252.1.50", 5001, scheme="https")
    assert r.status_code == 201 and r.json()["hostname"] == "nas.acme.ok.test" and not r.json()["protected"]
    assert svc(admin, a["id"], "cam.acme.ok.test", "192.168.88.20", 80).status_code == 201  # LAN del router
    assert svc(admin, b["id"], "nas.acme.ok.test", "10.252.2.5").status_code == 409        # nombre repetido
    # nombres compartidos con dominios de panel / clientes
    admin.put("/api/admin/settings", json={"main_domain": "panel.ok.test"}, headers=H)
    assert svc(admin, a["id"], "panel.ok.test", "10.252.1.50").status_code == 409
    assert admin.put(f"/api/tenant-domain?tenant_id={b['id']}", json={"domain": "cam.acme.ok.test"}, headers=H).status_code == 409
    assert admin.put("/api/admin/settings", json={"main_domain": "nas.acme.ok.test"}, headers=H).status_code == 409


def test_caddyfile_auth_and_isolation(admin):
    a, b = mk(admin, "acme"), mk(admin, "globex")
    assert svc(admin, a["id"], "nas.acme.ok.test", "10.252.1.50", auth_user="ana", auth_password="corta").status_code == 422
    r = svc(admin, a["id"], "nas.acme.ok.test", "10.252.1.50", 5001, scheme="https", auth_user="ana", auth_password="ClaveSegura1")
    assert r.status_code == 201 and r.json()["protected"] and r.json()["auth_user"] == "ana"
    cf = last_caddyfile(lambda x: "nas.acme.ok.test" in x)
    assert "\temail admin@example.com" in cf and "ask http://127.0.0.1:5000/internal/tls-ask" in cf
    assert "nas.acme.ok.test {" in cf and "reverse_proxy https://10.252.1.50:5001 {" in cf and "tls_insecure_skip_verify" in cf
    line = next(x for x in cf.splitlines() if x.strip().startswith("ana "))
    assert bcrypt.checkpw(b"ClaveSegura1", line.split()[1].encode())
    assert "https:// {" in cf and "reverse_proxy 127.0.0.1:5000" in cf

    sid = r.json()["id"]
    admin.patch(f"/api/services/{sid}", json={"clear_auth": True}, headers=H)
    assert "basic_auth" not in last_caddyfile(lambda x: "basic_auth" not in x)
    admin.patch(f"/api/services/{sid}", json={"enabled": False}, headers=H)
    assert "nas.acme.ok.test" not in last_caddyfile(lambda x: "nas.acme" not in x)
    admin.patch(f"/api/services/{sid}", json={"enabled": True}, headers=H)
    assert "nas.acme.ok.test" in last_caddyfile(lambda x: "nas.acme" in x)
    admin.patch(f"/api/admin/tenants/{a['id']}", json={"enabled": False}, headers=H)  # cliente suspendido
    assert "nas.acme.ok.test" not in last_caddyfile(lambda x: "nas.acme" not in x)
    admin.patch(f"/api/admin/tenants/{a['id']}", json={"enabled": True}, headers=H)

    # Certificados: sólo para servicios dados de alta cuyo DNS apunta aquí
    d = admin.app.state.domains
    assert d.allow_certificate("nas.acme.ok.test")
    svc(admin, a["id"], "ajeno.example.com", "10.252.1.51")
    assert not d.allow_certificate("ajeno.example.com")

    # Un cliente sólo ve y toca sus servicios
    admin.patch(f"/api/admin/tenants/{b['id']}", json={"password": "Temporal1"}, headers=H)
    with TestClient(admin.app) as cb:
        cb.post("/api/auth/login", json={"username": "globex", "password": "Temporal1"}, headers=H)
        cb.post("/api/me/password", json={"current": "Temporal1", "new": "Globex222"}, headers=H)
        assert cb.get(f"/api/services?tenant_id={a['id']}").json()["services"] == []
        assert cb.patch(f"/api/services/{sid}", json={"enabled": False}, headers=H).status_code == 404
        assert cb.delete(f"/api/services/{sid}", headers=H).status_code == 404
        r = cb.post("/api/services", json={"hostname": "x.globex.ok.test", "target_ip": "10.252.1.50",
                                           "target_port": 80, "tenant_id": a["id"]}, headers=H)
        assert r.status_code == 422  # se crea en SU red: 10.252.1.50 no es suya


def test_render_rejects_bad_auth_values():
    rows = [{"id": 1, "tenant_id": 1, "hostname": "x.ok.test", "auth_user": "a b", "auth_hash": "$2b$12$" + "x" * 53,
             "scheme": "http", "target_ip": "10.252.1.2", "target_port": 80}]
    assert "x.ok.test" not in caddy.render_caddyfile(5000, "", rows)  # nunca se publica sin la protección pedida
    ipaddress.ip_address("10.252.1.2")

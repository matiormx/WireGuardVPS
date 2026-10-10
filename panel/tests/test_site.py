from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import domains
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


def page(c, host, path="/"):
    return c.get(path, headers={"Host": host})


def test_public_site(admin):
    admin.put("/api/admin/settings", json={"main_domain": "vpn.ejemplo.com"}, headers=H)
    st = admin.get("/api/admin/site").json()
    assert st["enabled"] is False and st["title"] == "WireGuard Cloud" and st["has_plans"] is False
    assert admin.put("/api/admin/site", json={"enabled": True}, headers=H).status_code == 422       # sin dominio
    assert admin.put("/api/admin/site", json={"domains": ["vpn.ejemplo.com"]}, headers=H).status_code == 409  # el del panel
    assert admin.put("/api/admin/site", json={"email": "no-email"}, headers=H).status_code == 422
    st = admin.put("/api/admin/site", json={"domains": ["MiVPN.com", "www.mivpn.com", "mivpn.com"], "title": "Mi <VPN>",
                                            "headline": "Tu red & más", "email": "hola@mivpn.com",
                                            "legal": "Mi Empresa S.L.\nNIF B12345678"}, headers=H).json()
    assert st["domains"] == ["mivpn.com", "www.mivpn.com"] and st["url"] == "https://mivpn.com"
    # Mientras no se publique: el dominio no es de nadie (sin certificado) y muestra el panel
    assert "id=\"app\"" in page(admin, "mivpn.com").text
    assert not admin.app.state.domains.allow_certificate("mivpn.com")
    admin.put("/api/admin/site", json={"enabled": True}, headers=H)
    assert admin.app.state.domains.allow_certificate("mivpn.com") and admin.app.state.domains.allow_certificate("www.mivpn.com")
    # Nadie más puede usar esos dominios
    t = admin.post("/api/admin/tenants", json={"name": "Acme", "username": "acme", "password": "Password1"}, headers=H).json()
    assert admin.put(f"/api/tenant-domain?tenant_id={t['id']}", json={"domain": "www.mivpn.com"}, headers=H).status_code == 409

    html = page(admin, "mivpn.com").text
    assert "<h1>Tu red &amp; más</h1>" in html and "Mi &lt;VPN&gt;" in html and "<VPN>" not in html
    assert 'href="/dashboard"' in html and "hola@mivpn.com" in html and "NIF B12345678" in html
    assert 'id="planes"' not in html                                         # aún sin planes
    assert "id=\"app\"" in page(admin, "mivpn.com", "/dashboard").text       # el panel en /dashboard
    r = admin.get("/app", headers={"Host": "mivpn.com"}, follow_redirects=False)   # la ruta antigua redirige
    assert r.status_code == 301 and r.headers["location"] == "/dashboard"
    assert "id=\"app\"" in page(admin, "vpn.ejemplo.com").text               # el dominio del panel no cambia
    assert admin.get("/api/branding", headers={"Host": "mivpn.com"}).json()["title"] == "Mi <VPN>"
    man = admin.get("/manifest.webmanifest", headers={"Host": "www.mivpn.com"}).json()
    assert man["start_url"] == "/dashboard?source=pwa" and man["name"] == "Mi <VPN>"

    # Con planes y registro abierto
    with admin.app.state.db.conn() as c:
        c.execute("""INSERT INTO plans (name, description, price_cents, interval, max_devices, max_members, allow_exits, created_at)
                     VALUES ('Hogar', 'Para la familia', 499, 'month', 5, 3, 0, 0),
                            ('Pro', '', 1499, 'month', 20, 10, 1, 0),
                            ('Empresa', '', 4900, 'year', 100, 50, 1, 0),
                            ('Oculto', '', 100, 'month', 1, 0, 0, 0)""")
        c.execute("UPDATE plans SET public = 0 WHERE name = 'Oculto'")
    html = page(admin, "mivpn.com").text
    assert 'id="planes"' in html and "4,99 €" in html and "14,99 €" in html and "49,00 €<span>/año" in html
    assert "Oculto" not in html and "Más elegido" in html
    assert 'href="mailto:hola@mivpn.com?subject=Plan%20Hogar"' in html      # sin registro: contactar
    with admin.app.state.db.conn() as c:
        c.execute("INSERT OR REPLACE INTO settings VALUES ('billing_signup', '1'), ('stripe_secret_key', 'sk_test_x')")
    html = page(admin, "mivpn.com").text
    assert 'href="/dashboard#/signup?plan=1"' in html and "Crear cuenta" in html
    admin.put("/api/admin/site", json={"enabled": False}, headers=H)
    assert "id=\"app\"" in page(admin, "mivpn.com").text


def test_custom_panel_path_and_404(admin):
    admin.put("/api/admin/site", json={"domains": ["mivpn.com"], "enabled": True}, headers=H)
    for bad in ["api", "static", "a", "Mal Ruta", "x/y", "-guion", "app"]:
        assert admin.put("/api/admin/site", json={"path": bad}, headers=H).status_code == 422, bad
    st = admin.put("/api/admin/site", json={"path": "/Mi-Cuenta/"}, headers=H).json()
    assert st["path"] == "mi-cuenta"
    assert 'href="/mi-cuenta"' in page(admin, "mivpn.com").text
    assert "id=\"app\"" in page(admin, "mivpn.com", "/mi-cuenta").text
    assert admin.get("/app", headers={"Host": "mivpn.com"}, follow_redirects=False).headers["location"] == "/mi-cuenta"
    assert admin.get("/manifest.webmanifest", headers={"Host": "mivpn.com"}).json()["start_url"] == "/mi-cuenta?source=pwa"
    # 404: HTML en el navegador, JSON en la API
    r = admin.get("/dashboard", headers={"Host": "mivpn.com", "Accept": "text/html"})
    assert r.status_code == 404 and "Esta página no existe" in r.text and r.headers["content-type"].startswith("text/html")
    r = admin.get("/no/existe", headers={"Accept": "text/html,application/xhtml+xml"})
    assert r.status_code == 404 and "Volver al inicio" in r.text
    r = admin.get("/api/no-existe", headers={"Accept": "text/html"})
    assert r.status_code == 404 and r.json() == {"detail": "Not Found"}
    assert admin.get("/static/nada.js").status_code == 404


def test_install_from_panel_domain(admin):
    # Sin dominio del panel: se instala donde esté (p. ej. por IP)
    assert admin.get("/api/branding").json()["install_url"] is None
    assert 'rel="manifest"' in admin.get("/").text
    admin.put("/api/admin/settings", json={"main_domain": "vpn.ejemplo.com"}, headers=H)
    admin.put("/api/admin/site", json={"domains": ["mivpn.com"], "enabled": True}, headers=H)
    t = admin.post("/api/admin/tenants", json={"name": "Acme", "username": "acme", "password": "Password1"}, headers=H).json()
    admin.put(f"/api/tenant-domain?tenant_id={t['id']}", json={"domain": "vpn.acme.com"}, headers=H)
    for host in ("mivpn.com", "203.0.113.10:5000", "otro.ejemplo.com"):
        assert admin.get("/api/branding", headers={"Host": host}).json()["install_url"] == "https://vpn.ejemplo.com/?install=1", host
    assert 'rel="manifest"' not in page(admin, "mivpn.com", "/dashboard").text
    assert 'rel="manifest"' not in page(admin, "203.0.113.10:5000").text
    for host in ("vpn.ejemplo.com", "vpn.acme.com"):                 # el panel y los dominios de clientes
        assert admin.get("/api/branding", headers={"Host": host}).json()["install_url"] is None
        assert 'rel="manifest"' in page(admin, host).text

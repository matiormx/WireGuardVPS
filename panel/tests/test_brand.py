from __future__ import annotations

import base64
import struct
import zlib

import pytest
from fastapi.testclient import TestClient

from app import brand, domains
from app.main import create_app

H = {"X-WGP": "1"}


def png(w, h):
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + b"\x7f\x5c\xff\xff" * w for _ in range(h))
    return (brand.PNG_SIG + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def files(**over):
    out = {k: "data:image/png;base64," + base64.b64encode(png(s, s)).decode() for k, s in brand.FILES.items()}
    out.update(over)
    return out


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


def test_name(admin):
    st = admin.get("/api/admin/brand").json()
    assert st["name"] == "WireGuard Cloud" and st["short_name"] == "WG Cloud" and not st["custom_logo"]
    html = admin.get("/").text
    assert "<title>WireGuard Cloud</title>" in html and 'content="WG Cloud"' in html and "__" not in html
    assert admin.put("/api/admin/brand", json={"name": "   "}, headers=H).status_code == 422
    assert admin.put("/api/admin/brand", json={"name": "x" * 41}, headers=H).status_code == 422
    st = admin.put("/api/admin/brand", json={"name": " Red  <Segura> ", "short_name": "RedSegura"}, headers=H).json()
    assert st["name"] == "Red <Segura>" and st["short_name"] == "RedSegura" and st["version"] != "2"
    html = admin.get("/").text
    assert "<title>Red &lt;Segura&gt;</title>" in html and 'content="RedSegura"' in html and f"?v={st['version']}" in html
    assert admin.get("/api/branding").json()["title"] == "Red <Segura>"
    man = admin.get("/manifest.webmanifest").json()
    assert man["name"] == "Red <Segura>" and man["short_name"] == "RedSegura"
    assert all(i["src"].startswith("/brand/") and i["src"].endswith(f"?v={st['version']}") for i in man["icons"])
    # la página pública toma el nombre si no tiene uno propio
    admin.put("/api/admin/site", json={"domains": ["mivpn.com"], "enabled": True}, headers=H)
    assert "Red &lt;Segura&gt;" in admin.get("/", headers={"Host": "mivpn.com"}).text


def test_logo(admin):
    # sin logo propio: los iconos por defecto
    r = admin.get("/brand/icon-192.png")
    assert r.status_code == 200 and r.content.startswith(brand.PNG_SIG)
    assert admin.get("/brand/logo").headers["content-type"].startswith("image/svg+xml")
    assert admin.get("/brand/../app.js").status_code == 404 and admin.get("/brand/otro.png").status_code == 404
    # validación
    assert admin.put("/api/admin/brand/logo", json={"files": {"icon-192.png": "x"}}, headers=H).status_code == 422
    bad = files(**{"icon-192.png": base64.b64encode(png(100, 100)).decode()})
    assert admin.put("/api/admin/brand/logo", json={"files": bad}, headers=H).status_code == 422
    notpng = files(**{"favicon.png": base64.b64encode(b"<svg onload=alert(1)>").decode()})
    assert admin.put("/api/admin/brand/logo", json={"files": notpng}, headers=H).status_code == 422
    assert admin.put("/api/admin/brand/logo", json={"files": files(), "background": "red"}, headers=H).status_code == 422
    st = admin.put("/api/admin/brand/logo", json={"files": files(), "background": "#FFFFFF"}, headers=H).json()
    assert st["custom_logo"] and st["background"] == "#ffffff"
    r = admin.get(f"/brand/logo?v={st['version']}")
    assert r.headers["content-type"] == "image/png" and r.content == png(512, 512)
    assert "immutable" in r.headers["cache-control"] and r.headers["x-content-type-options"] == "nosniff"
    assert admin.get("/brand/logo", headers={"If-None-Match": r.headers["etag"]}).status_code == 304
    assert admin.get("/brand/apple-touch-icon.png").content == png(180, 180)
    # en las copias de seguridad (está en la base de datos)
    with admin.app.state.db.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM brand_files").fetchone()[0] == 5
    # sin sesión también se sirve (login); la API no
    admin.post("/api/auth/logout", headers=H)
    assert admin.get("/brand/favicon.png").content == png(64, 64)
    assert admin.put("/api/admin/brand", json={"name": "x"}, headers=H).status_code in (401, 403)
    admin.post("/api/auth/login", json={"username": "admin", "password": "AdminPass1"}, headers=H)
    st = admin.delete("/api/admin/brand/logo", headers=H).json()
    assert not st["custom_logo"] and admin.get("/brand/logo").headers["content-type"].startswith("image/svg+xml")
    assert admin.put("/api/admin/site", json={"path": "brand"}, headers=H).status_code == 422

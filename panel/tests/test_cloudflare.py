from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from app import cfdns, domains
from app.main import create_app

H = {"X-WGP": "1"}


class FakeCF:
    def __init__(self):
        self.records = {}
        self.n = 0
        self.zones = [{"id": "z1", "name": "wgcloud.app", "account": {"id": "a" * 32}},
                      {"id": "z2", "name": "otro.com", "account": {"id": "b" * 32}}]
        self.mails = []
        self.patches = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, code, data):
                body = json.dumps(data).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def handle_any(self):
                auth = self.headers.get("Authorization")
                url = urllib.parse.urlparse(self.path)
                q = dict(urllib.parse.parse_qsl(url.query))
                parts = url.path.strip("/").split("/")
                # «token-cuenta»: token de cuenta (sólo se valida en /accounts/<id>/tokens/verify)
                if auth == "Bearer token-cuenta":
                    if parts == ["user", "tokens", "verify"] or (parts[-2:] == ["tokens", "verify"] and parts[1] != "a" * 32):
                        return self.reply(401, {"success": False, "errors": [{"code": 1000, "message": "Invalid API Token"}]})
                elif auth != "Bearer buen-token":
                    return self.reply(403, {"success": False, "errors": [{"message": "Invalid API Token"}]})
                if parts[0] == "accounts" and parts[2:] == ["tokens", "verify"]:
                    return self.reply(200, {"success": True, "result": {"status": "active"}})
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                if parts == ["user", "tokens", "verify"]:
                    return self.reply(200, {"success": True, "result": {"status": "active"}})
                if parts == ["zones"]:
                    zones = [z for z in fake.zones if z["account"]["id"] == q.get("account.id", z["account"]["id"])]
                    return self.reply(200, {"success": True, "result": zones})
                if parts[0] == "accounts" and parts[2:] == ["email", "sending", "send"]:
                    if parts[1] != "a" * 32:
                        return self.reply(403, {"success": False, "errors": [{"code": 10102, "message": "Token lacks email sending permission"}]})
                    fake.mails.append(body)
                    bounced = [t for t in body["to"] if t.startswith("rebota@")]
                    return self.reply(200, {"success": True, "result": {"delivered": [t for t in body["to"] if t not in bounced],
                                                                        "permanent_bounces": bounced, "queued": []}})
                zone = parts[1]
                recs = [r for r in fake.records.values() if r["zone"] == zone]
                if self.command == "GET":
                    if "name" in q:
                        recs = [r for r in recs if r["name"] == q["name"]]
                    if "comment.startswith" in q:
                        recs = [r for r in recs if (r.get("comment") or "").startswith(q["comment.startswith"])]
                    return self.reply(200, {"success": True, "result": recs, "result_info": {"total_pages": 1}})
                if self.command == "POST":
                    fake.n += 1
                    rid = f"r{fake.n}"
                    fake.records[rid] = {**body, "id": rid, "zone": zone}
                    return self.reply(200, {"success": True, "result": fake.records[rid]})
                rid = parts[3]
                if self.command == "PUT":
                    fake.records[rid] = {**body, "id": rid, "zone": zone}
                    return self.reply(200, {"success": True, "result": fake.records[rid]})
                if self.command == "DELETE":
                    fake.records.pop(rid)
                    return self.reply(200, {"success": True, "result": {"id": rid}})
                if self.command == "PATCH":
                    fake.records[rid].update(body)
                    fake.patches.append((fake.records[rid]["name"], body))
                    return self.reply(200, {"success": True, "result": fake.records[rid]})

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = handle_any

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def names(self, zone="z1"):
        return sorted(r["name"] for r in self.records.values() if r["zone"] == zone)


@pytest.fixture()
def env(tmp_path, monkeypatch):
    fake = FakeCF()
    monkeypatch.setattr(cfdns, "API", fake.url)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
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
        yield c, fake
    fake.server.shutdown()


def tenant(c, name, user):
    return c.post("/api/admin/tenants", json={"name": name, "username": user, "password": "Password1"}, headers=H).json()


def test_labels():
    assert cfdns.dns_label("Juan_Pérez.92") == "juan-p-rez-92" and cfdns.dns_label("___") == "cliente"


def test_cloudflare_subdomains(env):
    c, fake = env
    acme = tenant(c, "Acme", "acme")
    assert acme["subdomain"] == "acme" and acme["public_host"] is None            # aún sin Cloudflare
    tenant(c, "Web SL", "WWW")                                                       # «www» está reservado
    # token malo / dominio sin acceso
    r = c.post("/api/admin/cloudflare/zones", json={"token": "malo"}, headers=H)
    assert r.status_code == 400 and "Invalid API Token" in r.json()["detail"]
    assert [z["name"] for z in c.post("/api/admin/cloudflare/zones", json={"token": "buen-token"}, headers=H).json()["zones"]] == ["wgcloud.app", "otro.com"]
    assert c.put("/api/admin/cloudflare", json={"token": "buen-token", "zone": "noesmio.com"}, headers=H).status_code == 422
    v = c.put("/api/admin/cloudflare", json={"token": "buen-token", "zone": "WGCloud.app"}, headers=H).json()
    assert v["zone"] == "wgcloud.app" and v["has_token"] and not v["enabled"] and fake.records == {}
    assert "token" not in json.dumps(v).replace("has_token", "")
    v = c.put("/api/admin/cloudflare", json={"enabled": True}, headers=H).json()
    assert v["state"]["ok"] and v["state"]["records"] == 4 and v["ip"] == "203.0.113.10"
    assert fake.names() == ["*.acme.wgcloud.app", "*.www-2.wgcloud.app", "acme.wgcloud.app", "www-2.wgcloud.app"]
    rec = next(r for r in fake.records.values() if r["name"] == "acme.wgcloud.app")
    assert rec["content"] == "203.0.113.10" and rec["proxied"] is False and rec["type"] == "A" and rec["comment"].startswith("wgp:")
    # el cliente ve su dirección y los puertos abiertos la usan
    t = c.get(f"/api/admin/tenants/{acme['id']}").json()
    assert t["public_host"] == "acme.wgcloud.app"
    assert c.get(f"/api/forwards?tenant_id={acme['id']}").json()["public_host"] == "acme.wgcloud.app"
    # registros existentes que no son del panel: no se tocan
    fake.records["ext"] = {"id": "ext", "zone": "z1", "type": "A", "name": "globex.wgcloud.app", "content": "1.2.3.4"}
    g = tenant(c, "Globex", "globex")
    v = c.post("/api/admin/cloudflare/sync", headers=H).json()
    assert v["state"]["ok"] is False and "globex.wgcloud.app" in v["state"]["error"]
    assert fake.records["ext"]["content"] == "1.2.3.4" and "*.globex.wgcloud.app" in fake.names()
    # el admin cambia el subdominio: se mueve el registro
    assert c.put(f"/api/admin/tenants/{g['id']}/subdomain", json={"subdomain": "acme"}, headers=H).status_code == 409
    assert c.put(f"/api/admin/tenants/{g['id']}/subdomain", json={"subdomain": "www"}, headers=H).status_code == 422
    r = c.put(f"/api/admin/tenants/{g['id']}/subdomain", json={"subdomain": "globex-sa"}, headers=H).json()
    assert r["host"] == "globex-sa.wgcloud.app" and "globex-sa.wgcloud.app" in fake.names() and "*.globex.wgcloud.app" not in fake.names()
    assert c.get("/api/admin/cloudflare").json()["state"]["ok"] is True
    # alguien cambia la IP a mano en Cloudflare: se corrige
    rec = next(r for r in fake.records.values() if r["name"] == "acme.wgcloud.app")
    rec["content"] = "9.9.9.9"
    c.post("/api/admin/cloudflare/sync", headers=H)
    assert next(r for r in fake.records.values() if r["name"] == "acme.wgcloud.app")["content"] == "203.0.113.10"
    # sin comodín: sólo el subdominio
    c.put("/api/admin/cloudflare", json={"wildcard": False}, headers=H)
    assert not any(n.startswith("*.") for n in fake.names())
    # borrar un cliente borra su registro
    c.delete(f"/api/admin/tenants/{g['id']}", headers=H)
    c.post("/api/admin/cloudflare/sync", headers=H)
    assert "globex-sa.wgcloud.app" not in fake.names()
    # desconectar: borra todos los del panel (no el ajeno) y olvida el token
    v = c.delete("/api/admin/cloudflare", headers=H).json()
    assert fake.names() == ["globex.wgcloud.app"] and not v["has_token"] and v["zone"] == ""


def test_zone_names_belong_to_tenant(env, monkeypatch):
    c, fake = env
    a, b = tenant(c, "Acme", "acme"), tenant(c, "Beta", "beta")
    c.put("/api/admin/cloudflare", json={"token": "buen-token", "zone": "wgcloud.app", "enabled": True}, headers=H)
    put = lambda tid, host: c.put(f"/api/tenant-domain?tenant_id={tid}", json={"domain": host}, headers=H)
    assert put(a["id"], "panel.acme.wgcloud.app").status_code == 200
    r = put(b["id"], "panel2.acme.wgcloud.app")
    assert r.status_code == 409 and "beta.wgcloud.app" in r.json()["detail"]
    assert put(b["id"], "wgcloud.app").status_code == 409
    assert put(b["id"], "vpn.beta-externo.com").status_code == 200       # otros dominios, como siempre


def test_cloudflare_email(env):
    c, fake = env
    assert c.post("/api/admin/alerts-config/test-email", json={"email": "yo@ejemplo.com"}, headers=H).status_code == 409
    # sin token de Cloudflare
    r = c.put("/api/admin/alerts-config", json={"email_provider": "cloudflare", "cf_from": "avisos@wgcloud.app"}, headers=H)
    assert r.status_code == 422
    # con el token de Subdominios; la cuenta se deduce del dominio del remitente
    c.put("/api/admin/cloudflare", json={"token": "buen-token", "zone": "wgcloud.app"}, headers=H)
    # con la cuenta conocida no se exige que el remitente sea de un dominio de DNS (lo valida Cloudflare al enviar);
    # sin ella, se deduce del dominio y debe verse con el token
    with c.app.state.db.conn() as db:
        db.execute("DELETE FROM settings WHERE key = 'cf_account'")
    assert c.put("/api/admin/alerts-config", json={"cf_from": "Avisos <avisos@noesmio.org>"}, headers=H).status_code == 422
    assert c.put("/api/admin/alerts-config", json={"cf_from": "no-es-email"}, headers=H).status_code == 422
    cfg = c.put("/api/admin/alerts-config", json={"email_provider": "cloudflare", "cf_from": "Avisos VPN <avisos@wgcloud.app>"}, headers=H).json()
    assert cfg["email"] == {"provider": "cloudflare", "ready": True}
    assert cfg["cloudflare"]["account"] == "a" * 32 and cfg["cloudflare"]["dns_token"] and not cfg["cloudflare"]["own_token"]
    assert c.post("/api/admin/alerts-config/test-email", json={"email": "yo@ejemplo.com"}, headers=H).json() == {"ok": True}
    m = fake.mails[-1]
    assert m["to"] == ["yo@ejemplo.com"] and m["from"] == {"address": "avisos@wgcloud.app", "name": "Avisos VPN"}
    assert "Prueba" in m["subject"] and "WireGuard Cloud" in m["text"] and m["html"].startswith("<div")
    # rebote y falta de permiso: error claro
    r = c.post("/api/admin/alerts-config/test-email", json={"email": "rebota@ejemplo.com"}, headers=H)
    assert r.status_code == 409 and "rechazada" in r.json()["detail"]
    c.put("/api/admin/alerts-config", json={"cf_account": "b" * 32}, headers=H)
    r = c.post("/api/admin/alerts-config/test-email", json={"email": "yo@ejemplo.com"}, headers=H)
    assert r.status_code == 409 and "10102" in r.json()["detail"]
    assert c.put("/api/admin/alerts-config", json={"cf_account": "xyz"}, headers=H).status_code == 422
    # los usuarios ya pueden añadir su email como canal de avisos
    assert c.get("/api/alerts").json()["available"]["email"] is True
    # volver a SMTP (sin configurar): el email deja de estar disponible
    assert c.put("/api/admin/alerts-config", json={"email_provider": "smtp"}, headers=H).json()["email"]["ready"] is False


def test_account_token(env):
    c, fake = env
    tenant(c, "Acme", "acme")
    r = c.post("/api/admin/cloudflare/zones", json={"token": "token-cuenta"}, headers=H)
    assert r.status_code == 400 and "ID de cuenta" in r.json()["detail"]
    assert c.post("/api/admin/cloudflare/zones", json={"token": "token-cuenta", "account": "xyz"}, headers=H).status_code == 422
    r = c.post("/api/admin/cloudflare/zones", json={"token": "token-cuenta", "account": "A" * 32}, headers=H).json()
    assert [z["name"] for z in r["zones"]] == ["wgcloud.app"]                 # sólo los de esa cuenta
    v = c.put("/api/admin/cloudflare", json={"token": "token-cuenta", "account": "a" * 32, "zone": "wgcloud.app", "enabled": True}, headers=H).json()
    assert v["account"] == "a" * 32 and v["state"]["ok"] and "acme.wgcloud.app" in fake.names()
    # el email por Cloudflare usa esa misma cuenta
    cfg = c.put("/api/admin/alerts-config", json={"email_provider": "cloudflare", "cf_from": "avisos@wgcloud.app"}, headers=H).json()
    assert cfg["cloudflare"]["account"] == "a" * 32 and cfg["email"]["ready"]


def rec(fake, name):
    return next(r for r in fake.records.values() if r["name"] == name)


def test_default_address_works_from_creation(env):
    c, fake = env
    c.put("/api/admin/settings", json={"main_domain": "vpn.wgcloud.app"}, headers=H)
    c.put("/api/admin/cloudflare", json={"token": "buen-token", "zone": "wgcloud.app", "enabled": True}, headers=H)
    a = tenant(c, "Acme", "acme")
    b = tenant(c, "Vpn SL", "vpn")                                              # «vpn» lo usa el panel
    assert b["subdomain"] == f"vpn-{b['id']}"
    c.post("/api/admin/cloudflare/sync", headers=H)
    assert "acme.wgcloud.app" in fake.names()
    host = {"Host": "acme.wgcloud.app"}
    # operativa desde el alta: su panel con su marca, certificado permitido
    assert c.get("/api/branding", headers=host).json()["title"] == "Acme"
    assert c.app.state.domains.allow_certificate("acme.wgcloud.app")
    assert not c.app.state.domains.allow_certificate("nadie.wgcloud.app")
    assert c.get(f"/api/tenant-domain?tenant_id={a['id']}").json()["default_domain"] == "acme.wgcloud.app"
    # nadie más puede usarla como dominio propio
    r = c.put(f"/api/tenant-domain?tenant_id={b['id']}", json={"domain": "acme.wgcloud.app"}, headers=H)
    assert r.status_code == 409
    # sólo ese cliente entra por ahí
    c.post("/api/auth/logout", headers=H)
    assert c.post("/api/auth/login", json={"username": "vpn", "password": "Password1"}, headers={**H, **host}).status_code == 403
    assert c.post("/api/auth/login", json={"username": "acme", "password": "Password1"}, headers={**H, **host}).status_code == 200
    # el cliente la cambia
    c.post("/api/me/password", json={"current": "Password1", "new": "Password22"}, headers={**H, **host})
    assert c.put("/api/me/subdomain", json={"subdomain": "vpn"}, headers=H).status_code == 422
    assert c.put("/api/me/subdomain", json={"subdomain": f"vpn-{b['id']}"}, headers=H).status_code == 409
    r = c.put("/api/me/subdomain", json={"subdomain": "acme-sl"}, headers=H).json()
    assert r["host"] == "acme-sl.wgcloud.app" and "acme-sl.wgcloud.app" in fake.names() and "acme.wgcloud.app" not in fake.names()
    assert c.get("/api/branding", headers={"Host": "acme-sl.wgcloud.app"}).json()["title"] == "Acme"
    assert c.get("/api/branding", headers=host).json()["tenant"] is False          # la antigua ya no es suya


def test_orange_cloud(env):
    c, fake = env
    c.put("/api/admin/settings", json={"main_domain": "vpn.wgcloud.app"}, headers=H)
    a, b = tenant(c, "Acme", "acme"), tenant(c, "Beta", "beta")
    fake.records["panel"] = {"id": "panel", "zone": "z1", "type": "A", "name": "vpn.wgcloud.app", "content": "203.0.113.10", "proxied": False}
    v = c.put("/api/admin/cloudflare", json={"token": "buen-token", "zone": "wgcloud.app", "enabled": True}, headers=H).json()
    assert not rec(fake, "acme.wgcloud.app")["proxied"] and v["proxy_default"] is False
    assert v["proxy_hosts"] == [{"host": "vpn.wgcloud.app", "kind": "panel", "proxied": False, "known": False, "endpoint": False}]
    # por defecto naranja: todos los clientes (y su comodín)
    c.put("/api/admin/cloudflare", json={"proxy_default": True}, headers=H)
    assert rec(fake, "acme.wgcloud.app")["proxied"] and rec(fake, "*.beta.wgcloud.app")["proxied"]
    assert rec(fake, "acme.wgcloud.app")["ttl"] == 1
    # un cliente en gris
    r = c.put(f"/api/admin/tenants/{b['id']}/proxy", json={"proxied": False}, headers=H).json()
    assert r == {"proxied": False, "custom": True, "state": r["state"]}
    assert not rec(fake, "beta.wgcloud.app")["proxied"] and rec(fake, "acme.wgcloud.app")["proxied"]
    t = c.get(f"/api/admin/tenants/{a['id']}").json()
    assert t["cf_proxied"] is True and t["cf_proxy_custom"] is False
    # puertos: con nube naranja se usa la dirección del servidor; en gris, la del cliente
    assert c.get(f"/api/forwards?tenant_id={a['id']}").json()["public_host"] == "203.0.113.10"
    assert c.get(f"/api/forwards?tenant_id={b['id']}").json()["public_host"] == "beta.wgcloud.app"
    # con proxy, el DNS apunta a Cloudflare y aun así se da por bueno (y se emite el certificado)
    doms = c.app.state.domains
    from app import domains as dmod
    orig = dmod.Domains.resolve
    try:
        dmod.Domains.resolve = staticmethod(lambda host: ["104.16.1.1"])
        assert doms.dns_status("acme.wgcloud.app")["ok"] and doms.dns_status("acme.wgcloud.app")["proxied"]
        assert doms.dns_status("nas.acme.wgcloud.app")["proxied"]
        assert not doms.dns_status("beta.wgcloud.app")["ok"]                       # gris: debe apuntar aquí
    finally:
        dmod.Domains.resolve = orig
    # dominio del panel: sólo se cambia la nube del registro existente
    v = c.put("/api/admin/cloudflare/proxy", json={"host": "vpn.wgcloud.app", "proxied": True}, headers=H).json()
    assert fake.records["panel"]["proxied"] is True and fake.records["panel"]["content"] == "203.0.113.10"
    assert v["proxy_hosts"][0]["proxied"] is True
    assert c.put("/api/admin/cloudflare/proxy", json={"host": "otro.com", "proxied": True}, headers=H).status_code == 422
    # el endpoint de WireGuard nunca por el proxy
    c.put("/api/admin/cloudflare/proxy", json={"host": "vpn.wgcloud.app", "proxied": False}, headers=H)
    assert c.put("/api/admin/wg-settings", json={"endpoint": "vpn.wgcloud.app"}, headers=H).status_code == 200
    assert c.get("/api/admin/cloudflare").json()["proxy_hosts"][0]["endpoint"] is True
    r = c.put("/api/admin/cloudflare/proxy", json={"host": "vpn.wgcloud.app", "proxied": True}, headers=H)
    assert r.status_code == 409 and "WireGuard" in r.json()["detail"]

    # y al revés: un nombre con nube naranja no puede ser el endpoint
    c.put("/api/admin/wg-settings", json={"endpoint": ""}, headers=H)
    r = c.put("/api/admin/wg-settings", json={"endpoint": "acme.wgcloud.app"}, headers=H)
    assert r.status_code == 409 and "nube naranja" in r.json()["detail"]

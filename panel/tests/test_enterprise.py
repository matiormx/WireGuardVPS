from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import domains, wg
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
    return tmp_path


def client(env):
    return TestClient(create_app())


def login(c, user, password, new=None):
    r = c.post("/api/auth/login", json={"username": user, "password": password}, headers=H)
    assert r.status_code == 200, r.text
    if new:
        assert c.post("/api/me/password", json={"current": password, "new": new}, headers=H).status_code == 200
    return r.json()


def test_net_index_encoding():
    net = wg.ipaddress.IPv4Network("10.20.3.0/24")
    idx = wg.org_net_index(net)
    assert idx < 0 and wg.tenant_network(None, idx) == net


def test_enterprise_flow(env):
    with client(env) as admin, client(env) as org, client(env) as inst:
        login(admin, "admin", "admin", "AdminPass1")
        other = admin.post("/api/admin/tenants", json={"name": "Otro", "username": "otro", "password": "Password1"},
                           headers=H).json()
        listing = admin.get("/api/admin/orgs").json()
        assert listing["suggested_network"] == "10.20.0.0/16" and listing["orgs"] == []
        base = {"name": "Celec S.L.", "username": "celec", "password": "Password1", "max_installs": 2, "max_devices": 15}
        # bloques no válidos
        for bad, code in (("10.252.0.0/16", 422), ("8.8.0.0/16", 422), ("10.20.0.0/25", 422), ("nope", 422)):
            r = admin.post("/api/admin/orgs", json={**base, "network": bad}, headers=H)
            assert r.status_code == code, (bad, r.text)
        o = admin.post("/api/admin/orgs", json=base, headers=H)
        assert o.status_code == 201, o.text
        o = o.json()
        assert o["network"] == "10.20.0.0/16" and o["network_capacity"] == 256
        assert admin.post("/api/admin/orgs", json={**base, "username": "otra", "network": "10.20.128.0/17"},
                          headers=H).status_code == 422          # se solapa con el de celec
        assert admin.post("/api/admin/orgs", json={**base, "username": "otro"}, headers=H).status_code == 409
        assert admin.get("/api/admin/orgs").json()["suggested_network"] == "10.21.0.0/16"
        assert (env / "wireguard" / "wgp" / "blocks.list").read_text().split() == ["10.20.0.0/16"]

        # la cuenta Enterprise entra y gestiona sus instalaciones
        assert login(org, "celec", "Password1")["role"] == "org"
        assert org.get("/api/admin/tenants").status_code == 403   # primero cambiar la contraseña
        assert org.post("/api/me/password", json={"current": "Password1", "new": "Password2"}, headers=H).status_code == 200
        me = org.get("/api/me").json()
        assert me["role"] == "org" and me["org"]["network"] == "10.20.0.0/16" and me["org"]["installs"] == 0
        assert org.get("/api/admin/tenants").json() == []
        a = org.post("/api/admin/tenants", json={"name": "Oficina Madrid", "username": "celec-mad", "password": "Password1",
                                                 "max_devices": 10}, headers=H)
        assert a.status_code == 201, a.text
        a = a.json()
        assert a["network"] == "10.20.0.0/24" and a["org_id"] == o["id"] and a["max_devices"] == 10
        b = org.post("/api/admin/tenants", json={"name": "Oficina BCN", "username": "celec-bcn", "password": "Password1",
                                                 "max_devices": 10}, headers=H).json()
        assert b["network"] == "10.20.1.0/24" and b["max_devices"] == 5     # sólo quedaban 5 de 15
        r = org.post("/api/admin/tenants", json={"name": "Tres", "username": "celec-3", "password": "Password1"}, headers=H)
        assert r.status_code == 409 and "2 instalaciones" in r.json()["detail"]
        assert {t["id"] for t in org.get("/api/admin/tenants").json()} == {a["id"], b["id"]}
        r = org.patch(f"/api/admin/tenants/{b['id']}", json={"max_devices": 6}, headers=H)
        assert r.status_code == 409 and "quedan 5" in r.json()["detail"]
        assert org.patch(f"/api/admin/tenants/{b['id']}", json={"allow_exits": False}, headers=H).status_code == 403
        assert org.patch(f"/api/admin/tenants/{b['id']}", json={"name": "BCN"}, headers=H).json()["name"] == "BCN"

        # dispositivos dentro del bloque Enterprise
        d = org.post("/api/devices", json={"tenant_id": a["id"], "name": "Portátil"}, headers=H)
        assert d.status_code == 201, d.text
        d = d.json()
        assert d["ip"] == "10.20.0.2"
        conf = org.get(f"/api/devices/{d['id']}/config").text
        assert "Address = 10.20.0.2/32" in conf
        assert org.post("/api/devices", json={"name": "x"}, headers=H).status_code == 400   # sin tenant_id
        groups = (env / "wireguard" / "wgp" / "tenants.list").read_text().split()
        assert {"10.20.0.0/24", "10.20.1.0/24", "10.252.1.0/24"} <= set(groups)
        assert "10.20.0.2/32" in (env / "wireguard" / "wg0.conf").read_text()

        # nada de otros clientes ni de la administración
        for url in (f"/api/admin/tenants/{other['id']}", f"/api/devices?tenant_id={other['id']}",
                    f"/api/services?tenant_id={other['id']}", f"/api/forwards?tenant_id={other['id']}",
                    f"/api/filters?tenant_id={other['id']}", f"/api/members?tenant_id={other['id']}",
                    f"/api/dns-zone?tenant_id={other['id']}", f"/api/tenant-domain?tenant_id={other['id']}",
                    f"/api/history/events?tenant_id={other['id']}"):
            assert org.get(url).status_code == 404, url
        assert org.delete(f"/api/admin/tenants/{other['id']}", headers=H).status_code == 404
        assert org.post("/api/devices", json={"tenant_id": other["id"], "name": "x"}, headers=H).status_code == 404
        od = admin.post("/api/devices", json={"tenant_id": other["id"], "name": "ajeno"}, headers=H).json()
        assert org.get(f"/api/devices/{od['id']}/config").status_code == 404
        assert org.delete(f"/api/devices/{od['id']}", headers=H).status_code == 404
        for url in ("/api/admin/orgs", "/api/admin/settings", "/api/admin/overview", "/api/admin/exits"):
            assert org.get(url).status_code == 403, url
        assert org.get("/api/devices").status_code == 400
        assert org.get("/api/billing").status_code == 403
        assert org.get(f"/api/members?tenant_id={a['id']}").status_code == 200
        assert org.get(f"/api/filters?tenant_id={a['id']}").status_code == 200

        # el responsable de una instalación entra como un cliente normal
        login(inst, "celec-mad", "Password1", "Password3")
        mine = inst.get("/api/devices").json()
        assert [x["ip"] for x in mine] == ["10.20.0.2"] and inst.get("/api/me").json()["network"] == "10.20.0.0/24"
        assert inst.get("/api/admin/tenants").status_code == 403

        # el admin ve las instalaciones y la cuenta con su uso
        s = admin.get(f"/api/admin/orgs/{o['id']}").json()
        assert s["installs"] == 2 and s["devices"] == 1 and s["devices_assigned"] == 15
        assert admin.patch(f"/api/admin/orgs/{o['id']}", json={"max_devices": 10}, headers=H).status_code == 409
        # deshabilitar la cuenta corta sus instalaciones
        assert admin.patch(f"/api/admin/orgs/{o['id']}", json={"enabled": False}, headers=H).status_code == 200
        assert org.get("/api/me").status_code == 401
        assert inst.get("/api/devices").status_code == 401
        assert "10.20.0.0/24" not in (env / "wireguard" / "wgp" / "tenants.list").read_text()
        assert admin.patch(f"/api/admin/orgs/{o['id']}", json={"enabled": True}, headers=H).status_code == 200
        assert "10.20.0.0/24" in (env / "wireguard" / "wgp" / "tenants.list").read_text()
        # borrar la cuenta borra sus instalaciones y su bloque
        assert admin.delete(f"/api/admin/orgs/{o['id']}", headers=H).status_code == 200
        assert [t["username"] for t in admin.get("/api/admin/tenants").json()] == ["otro"]
        assert (env / "wireguard" / "wgp" / "blocks.list").read_text() == ""


def test_router_lan_cannot_overlap_block(env):
    with client(env) as admin:
        login(admin, "admin", "admin", "AdminPass1")
        admin.post("/api/admin/orgs", json={"name": "E", "username": "ent", "password": "Password1",
                                            "network": "10.30.0.0/16"}, headers=H)
        t = admin.post("/api/admin/tenants", json={"name": "T", "username": "farmacia", "password": "Password1"}, headers=H)
        assert t.status_code == 201, t.text
        t = t.json()
        r = admin.post("/api/devices", json={"tenant_id": t["id"], "name": "r", "kind": "router",
                                             "lan_networks": ["10.30.5.0/24"]}, headers=H)
        assert r.status_code == 409
        # y un bloque no puede pisar la LAN de un router existente
        admin.post("/api/devices", json={"tenant_id": t["id"], "name": "r", "kind": "router",
                                         "lan_networks": ["10.40.1.0/24"]}, headers=H)
        r = admin.post("/api/admin/orgs", json={"name": "F", "username": "fff", "password": "Password1",
                                                "network": "10.40.0.0/16"}, headers=H)
        assert r.status_code == 422 and "10.40.1.0/24" in r.json()["detail"]


def test_dns_policy_for_block(env):
    with client(env) as admin:
        login(admin, "admin", "admin", "AdminPass1")
        o = admin.post("/api/admin/orgs", json={"name": "E", "username": "ent", "password": "Password1"}, headers=H).json()
        with client(env) as org:
            login(org, "ent", "Password1", "Password2")
            org.post("/api/admin/tenants", json={"name": "A", "username": "ent-a", "password": "Password1"}, headers=H)
            b = org.post("/api/admin/tenants", json={"name": "B", "username": "ent-b", "password": "Password1"},
                         headers=H).json()
        dns = admin.app.state.dns
        dns.reload_policies()
        assert o["network"] == "10.20.0.0/16"
        assert dns.policy_for("10.20.1.7").tenant_id == b["id"]
        assert dns.policy_for("10.20.9.7") is None

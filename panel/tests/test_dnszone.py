from __future__ import annotations

import asyncio
import sqlite3

import pytest
from dnslib import QTYPE, RCODE, RR, A, DNSRecord
from fastapi.testclient import TestClient

from app.db import Database
from app.main import create_app
from app.wg import generate_keypair

H = {"X-WGP": "1"}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("WG_CONF_DIR", str(tmp_path / "wireguard"))
    monkeypatch.setenv("WG_ENDPOINT", "203.0.113.10")
    monkeypatch.setenv("SESSION_SECRET", "x")
    monkeypatch.setenv("DNS_BIND", "127.0.0.1")
    monkeypatch.setenv("DNS_PORT", "0")
    monkeypatch.setenv("WG_DNS", "127.0.0.1")
    monkeypatch.setattr("app.dnsfilter.ListStore.refresh", lambda self: None)
    return tmp_path


@pytest.fixture()
def admin(env):
    with TestClient(create_app()) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": "admin"}, headers=H)
        c.post("/api/me/password", json={"current": "admin", "new": "AdminPass1"}, headers=H)
        yield c


def mk(c, username):
    return c.post("/api/admin/tenants", json={"name": username.title(), "username": username, "password": "Password1"}, headers=H).json()


def dev(c, tid, name):
    return c.post("/api/devices", json={"name": name, "tenant_id": tid}, headers=H).json()


def test_hostnames_records_and_suffixes(admin):
    a = mk(admin, "acme")
    d1 = dev(admin, a["id"], "Portátil de Ana")
    d2 = dev(admin, a["id"], "Portátil de Ana")
    assert d1["hostname"] == "portatil-de-ana" and d2["hostname"] == "portatil-de-ana-2"

    assert admin.patch(f"/api/devices/{d2['id']}", json={"hostname": "Bad Name"}, headers=H).status_code == 422
    assert admin.patch(f"/api/devices/{d2['id']}", json={"hostname": "portatil-de-ana"}, headers=H).status_code == 409
    assert admin.patch(f"/api/devices/{d2['id']}", json={"hostname": "Laptop-Pablo"}, headers=H).json()["hostname"] == "laptop-pablo"

    z = admin.post(f"/api/dns-zone/records?tenant_id={a['id']}", json={"name": "NAS", "ip": "10.252.1.50"}, headers=H).json()
    assert {"name": "nas", "ip": "10.252.1.50"} in [{k: r[k] for k in ("name", "ip")} for r in z["records"]]
    assert admin.post(f"/api/dns-zone/records?tenant_id={a['id']}", json={"name": "laptop-pablo", "ip": "1.2.3.4"}, headers=H).status_code == 409
    assert admin.post(f"/api/dns-zone/records?tenant_id={a['id']}", json={"name": "x", "ip": "999.1.1.1"}, headers=H).status_code == 422
    assert admin.patch(f"/api/devices/{d1['id']}", json={"hostname": "nas"}, headers=H).status_code == 409

    # Sufijos: sólo admin; van en la línea DNS de la configuración
    r = admin.put("/api/admin/dns-settings", json={"suffixes": ["VPN", "lan", "lan"]}, headers=H)
    assert r.json()["suffixes"] == ["vpn", "lan"]
    assert admin.put("/api/admin/dns-settings", json={"suffixes": ["mal sufijo"]}, headers=H).status_code == 422
    conf = admin.get(f"/api/devices/{d1['id']}/config").text
    assert "DNS = 10.252.0.1, vpn, lan" in conf

    # Reenvío propio: público o dentro de su red; nunca la red de otro cliente
    b = mk(admin, "globex")
    ok = admin.put(f"/api/dns-zone/upstreams?tenant_id={a['id']}", json={"upstreams": ["9.9.9.9", "10.252.1.50"]}, headers=H)
    assert ok.status_code == 200 and ok.json()["upstreams"] == ["9.9.9.9", "10.252.1.50"]
    for bad in (["10.252.2.5"], ["192.168.1.1"], ["10.252.0.1"], ["nope"]):
        assert admin.put(f"/api/dns-zone/upstreams?tenant_id={a['id']}", json={"upstreams": bad}, headers=H).status_code == 422

    # Un cliente no ve ni borra los registros de otro
    rec_id = z["records"][0]["id"]
    admin.patch(f"/api/admin/tenants/{b['id']}", json={"password": "Temporal1"}, headers=H)
    with TestClient(admin.app) as cb:
        cb.post("/api/auth/login", json={"username": "globex", "password": "Temporal1"}, headers=H)
        cb.post("/api/me/password", json={"current": "Temporal1", "new": "Globex222"}, headers=H)
        mine = cb.get(f"/api/dns-zone?tenant_id={a['id']}").json()
        assert mine["tenant_id"] == b["id"] and mine["records"] == [] and mine["suffixes"] == ["vpn", "lan"]
        assert cb.delete(f"/api/dns-zone/records/{rec_id}", headers=H).status_code == 404
        assert cb.put("/api/admin/dns-settings", json={"suffixes": ["x"]}, headers=H).status_code == 403


class Upstream(asyncio.DatagramProtocol):
    def __init__(self, ip):
        self.ip, self.names = ip, []

    def connection_made(self, t):
        self.t = t

    def datagram_received(self, data, addr):
        req = DNSRecord.parse(data)
        self.names.append(str(req.q.qname))
        reply = req.reply()
        reply.add_answer(RR(req.q.qname, QTYPE.A, rdata=A(self.ip), ttl=60))
        self.t.sendto(reply.pack(), addr)


def test_resolver_local_zone(admin):
    a, b = mk(admin, "acme"), mk(admin, "globex")
    da = dev(admin, a["id"], "Portátil Ana")
    db_ = dev(admin, b["id"], "Servidor Globex")
    admin.post(f"/api/dns-zone/records?tenant_id={a['id']}", json={"name": "nas", "ip": "10.252.1.50"}, headers=H)
    admin.put("/api/admin/dns-settings", json={"suffixes": ["vpn", "lan"]}, headers=H)
    dns = admin.app.state.dns

    async def run():
        loop = asyncio.get_running_loop()
        t1, up_default = await loop.create_datagram_endpoint(lambda: Upstream("1.1.1.1"), local_addr=("127.0.0.1", 0))
        dns.upstream_port = t1.get_extra_info("sockname")[1]

        async def ask(src, name, qtype="A"):
            return DNSRecord.parse(await dns.handle(DNSRecord.question(name, qtype).pack(), src))

        A_IP, B_IP = da["ip"], db_["ip"]
        r = await ask(A_IP, "portatil-ana.vpn")
        assert str(r.rr[0].rdata) == A_IP
        r = await ask(A_IP, "nas.lan")
        assert str(r.rr[0].rdata) == "10.252.1.50"
        r = await ask(A_IP, "nas")                       # nombre corto
        assert str(r.rr[0].rdata) == "10.252.1.50"
        r = await ask(A_IP, "nas.vpn", "AAAA")            # sin IPv6: NOERROR vacío
        assert r.header.rcode == RCODE.NOERROR and not r.rr
        r = await ask(A_IP, "servidor-globex.vpn")        # nombre de OTRO cliente
        assert r.header.rcode == RCODE.NXDOMAIN
        r = await ask(B_IP, "nas.vpn")
        assert r.header.rcode == RCODE.NXDOMAIN
        r = await ask(A_IP, "noexiste.lan")
        assert r.header.rcode == RCODE.NXDOMAIN

        # Inversa: la propia sí, la de otro cliente no
        rev = ".".join(reversed(A_IP.split("."))) + ".in-addr.arpa"
        r = await ask(A_IP, rev, "PTR")
        assert str(r.rr[0].rdata) == "portatil-ana.vpn."
        rev_b = ".".join(reversed(B_IP.split("."))) + ".in-addr.arpa"
        assert (await ask(A_IP, rev_b, "PTR")).header.rcode == RCODE.NXDOMAIN

        # Nada de los sufijos internos sale a Internet; lo público sí
        r = await ask(A_IP, "example.com")
        assert str(r.rr[0].rdata) == "1.1.1.1"
        assert up_default.names == ["example.com."]

        # Reenvío propio del cliente (todos los servidores escuchan en el mismo puerto de prueba)
        t2, up_own = await loop.create_datagram_endpoint(lambda: Upstream("9.9.9.9"), local_addr=("127.0.0.2", dns.upstream_port))
        pol = dns.policy_for(A_IP)
        dns.policies[1] = type(pol)(**{**pol.__dict__, "upstreams": ("127.0.0.2",)})
        r = await ask(A_IP, "example.com")               # caché distinta por servidor de reenvío
        assert str(r.rr[0].rdata) == "9.9.9.9" and up_own.names == ["example.com."]
        r = await ask(B_IP, "example.com")
        assert str(r.rr[0].rdata) == "1.1.1.1"
        t1.close()
        t2.close()

    asyncio.run(run())


def test_migration_backfills_hostnames(env):
    from app.config import load_settings
    s = load_settings()
    db = Database(s.data_dir / "panel.db")
    db.init("admin", "admin", generate_keypair)
    with db.conn() as c:
        c.execute("INSERT INTO tenants (name, username, password_hash, net_index, created_at) VALUES ('A','a','x',1,0)")
        for i, name in enumerate(["iPhone de Ana", "iPhone de Ana"], start=2):
            c.execute("INSERT INTO devices (tenant_id, name, ip, private_key, public_key, preshared_key, created_at, hostname)"
                      " VALUES (1, ?, ?, 'k', ?, 's', 0, NULL)", (name, f"10.252.1.{i}", f"p{i}"))
        c.execute("DELETE FROM settings WHERE key = 'dns_suffixes'")
    db.init("admin", "admin", generate_keypair)
    con = sqlite3.connect(s.data_dir / "panel.db")
    assert [r[0] for r in con.execute("SELECT hostname FROM devices ORDER BY id")] == ["iphone-de-ana", "iphone-de-ana-2"]
    assert con.execute("SELECT value FROM settings WHERE key = 'dns_suffixes'").fetchone()[0] == "vpn"

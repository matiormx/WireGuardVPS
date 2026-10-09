from __future__ import annotations

import asyncio
import socket
import struct

import pytest
from dnslib import QTYPE, RCODE, RR, A, DNSRecord
from fastapi.testclient import TestClient

from app import dnsfilter
from app.config import load_settings
from app.db import Database
from app.dnsfilter import DnsFilter, Policy, parse_list, safesearch_target
from app.main import create_app
from app.wg import generate_keypair

H = {"X-WGP": "1"}

SAMPLE = """
! AdGuard / uBlock (ABP)
||ads.example.com^
||tracker.net^$important
||cosmetic.com^$third-party
example.org##.banner
/regex-rule/
@@||cdn.ads.example.com^
@@||safe.tracker.net^|
@@/regex-exception/
# hosts
0.0.0.0 malware.bad   # comentario
127.0.0.1 localhost
::1 ip6-localhost
plain-domain.io
not a domain
*.wild.com
"""


def test_parse_list_formats():
    blocked, allowed = parse_list(SAMPLE)
    assert blocked == {"ads.example.com", "tracker.net", "malware.bad", "plain-domain.io"}
    assert allowed == {"cdn.ads.example.com", "safe.tracker.net"}


def test_normalize_domain():
    assert dnsfilter.normalize_domain(" Facebook.COM. ") == "facebook.com"
    assert dnsfilter.normalize_domain("||x.y^") == "x.y"
    assert dnsfilter.normalize_domain("*.tiktok.com") == "tiktok.com"
    assert dnsfilter.normalize_domain("not valid") is None
    assert dnsfilter.normalize_domain("localhost") is None


def test_safesearch_targets():
    assert safesearch_target("www.google.com") == "forcesafesearch.google.com"
    assert safesearch_target("google.es") == "forcesafesearch.google.com"
    assert safesearch_target("www.google.com.mx") == "forcesafesearch.google.com"
    assert safesearch_target("youtube.com") == "restrictmoderate.youtube.com"
    assert safesearch_target("www.bing.com") == "strict.bing.com"
    assert safesearch_target("mail.google.com") is None


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


def make_filter(env) -> DnsFilter:
    s = load_settings()
    db = Database(s.data_dir / "panel.db")
    db.init("admin", "admin", generate_keypair)
    f = DnsFilter(s, db)
    blocked, allowed = parse_list(SAMPLE)
    f.lists.data["ads"] = dnsfilter.CategoryData(frozenset(blocked), frozenset(allowed), 1.0)
    f.lists.data["adult"] = dnsfilter.CategoryData(frozenset({"adult.example"}), frozenset(), 1.0)
    return f


def test_decide_precedence(env):
    f = make_filter(env)
    p = Policy(1, frozenset({"ads"}), True, frozenset({"tracker.net"}), frozenset({"tiktok.com"}), frozenset({"10.252.1.9"}))
    ip = "10.252.1.2"
    assert f.decide("x.ads.example.com", p, ip) == ("block", None)          # subdominio de la lista
    assert f.decide("cdn.ads.example.com", p, ip) == ("forward", None)      # excepción @@ de la lista
    assert f.decide("tracker.net", p, ip) == ("forward", None)              # lista blanca del cliente
    assert f.decide("www.tiktok.com", p, ip) == ("block", None)             # lista negra del cliente
    assert f.decide("adult.example", p, ip) == ("forward", None)            # categoría no activada
    assert f.decide("www.google.com", p, ip) == ("safesearch", "forcesafesearch.google.com")
    assert f.decide("use-application-dns.net", p, ip) == ("nxdomain", None)
    assert f.decide("x.ads.example.com", p, "10.252.1.9") == ("forward", None)  # dispositivo exento
    assert f.decide("x.ads.example.com", None, ip) == ("forward", None)


def test_policy_lookup_by_tenant_network(env):
    f = make_filter(env)
    pol = Policy(7, frozenset({"ads"}), False, frozenset(), frozenset(), frozenset())
    f.policies = {3: pol}
    assert f.policy_for("10.252.3.44") is pol
    assert f.policy_for("10.252.4.1") is None
    assert f.policy_for("10.252.0.1") is None
    assert f.policy_for("8.8.8.8") is None


class FakeUpstream(asyncio.DatagramProtocol):
    """Servidor DNS de subida: responde 93.184.216.34 a todo y cuenta consultas."""

    def __init__(self):
        self.count = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.count += 1
        req = DNSRecord.parse(data)
        reply = req.reply()
        if req.q.qtype == QTYPE.A:
            reply.add_answer(RR(req.q.qname, QTYPE.A, rdata=A("93.184.216.34"), ttl=120))
        self.transport.sendto(reply.pack(), addr)


def test_end_to_end_udp_and_tcp(env):
    async def run():
        f = make_filter(env)
        loop = asyncio.get_running_loop()
        up_t, up = await loop.create_datagram_endpoint(FakeUpstream, local_addr=("127.0.0.1", 0))
        f.upstream_port = up_t.get_extra_info("sockname")[1]
        await f.start()
        assert f.running and f.port
        lists = make_filter(env).lists.data  # start() recarga desde disco (vacío en el test)
        f.lists.data.update(lists)
        f.policies = {1: Policy(1, frozenset({"ads"}), True, frozenset(), frozenset(), frozenset())}

        # Cliente sin política (127.0.0.1) por UDP: se reenvía y se cachea.
        def udp(name):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(DNSRecord.question(name).pack(), ("127.0.0.1", f.port))
            data = s.recv(4096)
            s.close()
            return DNSRecord.parse(data)

        r = await asyncio.to_thread(udp, "ads.example.com")
        assert str(r.rr[0].rdata) == "93.184.216.34"
        await asyncio.to_thread(udp, "ads.example.com")
        assert up.count == 1  # segunda vez desde la caché

        # Por TCP
        def tcp(name):
            s = socket.create_connection(("127.0.0.1", f.port), timeout=3)
            q = DNSRecord.question(name).pack()
            s.sendall(struct.pack("!H", len(q)) + q)
            (n,) = struct.unpack("!H", s.recv(2))
            data = b""
            while len(data) < n:
                data += s.recv(n - len(data))
            s.close()
            return DNSRecord.parse(data)

        r = await asyncio.to_thread(tcp, "example.net")
        assert str(r.rr[0].rdata) == "93.184.216.34"

        # Cliente del inquilino 1: bloqueo, búsqueda segura y canario DoH.
        r = DNSRecord.parse(await f.handle(DNSRecord.question("x.ads.example.com").pack(), "10.252.1.2"))
        assert str(r.rr[0].rdata) == "0.0.0.0"
        r = DNSRecord.parse(await f.handle(DNSRecord.question("x.ads.example.com", "AAAA").pack(), "10.252.1.2"))
        assert str(r.rr[0].rdata) == "::"
        r = DNSRecord.parse(await f.handle(DNSRecord.question("www.google.com").pack(), "10.252.1.2"))
        assert r.rr[0].rtype == QTYPE.CNAME and str(r.rr[0].rdata) == "forcesafesearch.google.com."
        assert str(r.rr[1].rdata) == "93.184.216.34"
        r = DNSRecord.parse(await f.handle(DNSRecord.question("use-application-dns.net").pack(), "10.252.1.2"))
        assert r.header.rcode == RCODE.NXDOMAIN
        st = f.tenant_stats(1)
        assert st["blocked_24h"] == 2 and st["queries_24h"] == 4
        assert st["top"][0]["domain"] == "x.ads.example.com"

        # Subida caída -> SERVFAIL (no se cuelga)
        up_t.close()
        f.cache.clear()
        r = DNSRecord.parse(await f.forward(DNSRecord.question("down.example").pack()))
        assert r.header.rcode == RCODE.SERVFAIL
        await f.stop()

    asyncio.run(run())


def test_filters_api_and_dns_list(env):
    with TestClient(create_app()) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": "admin"}, headers=H)
        c.post("/api/me/password", json={"current": "admin", "new": "AdminPass1"}, headers=H)
        t = c.post("/api/admin/tenants", json={"name": "Familia", "username": "familia", "password": "Password1"}, headers=H).json()
        other = c.post("/api/admin/tenants", json={"name": "Otro", "username": "otro", "password": "Password1"}, headers=H).json()
        d = c.post("/api/devices", json={"name": "Papá", "tenant_id": t["id"]}, headers=H).json()
        assert d["dns_filter"] is True
        dns_list = env / "wireguard" / "wgp" / "dns.list"
        assert dns_list.read_text() == ""

        cat = c.get("/api/filters/catalog").json()
        assert {x["key"] for x in cat["categories"]} == {"ads", "security", "adult", "gambling"}

        assert c.get("/api/filters").status_code == 400  # admin: falta tenant_id
        body = {"adult": True, "safesearch": True, "allowlist": ["Khanacademy.org"], "denylist": ["*.tiktok.com"]}
        r = c.put(f"/api/filters?tenant_id={t['id']}", json=body, headers=H)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["filters"]["adult"] and data["filters"]["safesearch"] and not data["filters"]["ads"]
        assert data["allowlist"] == ["khanacademy.org"] and data["denylist"] == ["tiktok.com"]
        assert dns_list.read_text().split() == [t["network"]]
        assert c.put(f"/api/filters?tenant_id={t['id']}", json={"denylist": ["no valido"]}, headers=H).status_code == 422

        dns = c.app.state.dns
        pol = dns.policy_for(d["ip"])
        assert pol and pol.safesearch and "adult" in pol.categories and "tiktok.com" in pol.deny
        assert dns.policy_for("10.252.2.5") is None or not dns.policy_for("10.252.2.5").active

        # Dispositivo exento
        c.patch(f"/api/devices/{d['id']}", json={"dns_filter": False}, headers=H)
        assert d["ip"] in dns.policy_for(d["ip"]).exempt

        # El cliente sólo ve y cambia sus filtros
        c.patch(f"/api/admin/tenants/{t['id']}", json={"password": "Temporal1"}, headers=H)
        c.post("/api/auth/logout", headers=H)
        c.post("/api/auth/login", json={"username": "familia", "password": "Temporal1"}, headers=H)
        c.post("/api/me/password", json={"current": "Temporal1", "new": "Familia22"}, headers=H)
        mine = c.get(f"/api/filters?tenant_id={other['id']}").json()
        assert mine["tenant_id"] == t["id"]
        r = c.put(f"/api/filters?tenant_id={other['id']}", json={"ads": True}, headers=H)
        assert r.json()["tenant_id"] == t["id"] and r.json()["filters"]["ads"]

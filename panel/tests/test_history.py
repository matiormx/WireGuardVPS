from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

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
    with TestClient(create_app()) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": "admin"}, headers=H)
        c.post("/api/me/password", json={"current": "admin", "new": "AdminPass1"}, headers=H)
        yield c


def mk(c, username):
    return c.post("/api/admin/tenants", json={"name": username.title(), "username": username, "password": "Password1"},
                  headers=H).json()


def peer(rx, tx, online=True, hs=None, endpoint="198.51.100.7:51234"):
    return {"rx": rx, "tx": tx, "online": online, "last_handshake": hs, "endpoint": endpoint}


def test_traffic_events_and_alerts(admin):
    mon = admin.app.state.monitor
    a, b = mk(admin, "acme"), mk(admin, "globex")
    rt = admin.post("/api/devices", json={"name": "MikroTik", "tenant_id": a["id"], "kind": "router",
                                          "lan_networks": ["192.168.88.0/24"]}, headers=H).json()
    ph = admin.post("/api/devices", json={"name": "iPhone", "tenant_id": a["id"]}, headers=H).json()
    gb = admin.post("/api/devices", json={"name": "PC Globex", "tenant_id": b["id"]}, headers=H).json()
    assert rt["monitor"] is True and ph["monitor"] is False  # los routers se vigilan por defecto
    assert admin.patch(f"/api/devices/{ph['id']}", json={"monitor": True}, headers=H).json()["monitor"] is True
    admin.patch(f"/api/devices/{ph['id']}", json={"monitor": False}, headers=H)

    t0 = time.time() - 3 * 3600
    k_rt, k_ph, k_gb = rt["public_key"], ph["public_key"], gb["public_key"]
    assert mon.tick(t0, {k_rt: peer(1000, 5000, hs=t0), k_gb: peer(10, 10, hs=t0)}) == []  # primera lectura
    assert mon.tick(t0 + 60, {k_rt: peer(3000, 9000, hs=t0), k_ph: peer(50, 70, hs=t0), k_gb: peer(110, 210, hs=t0)}) == []
    # wg0 reiniciada: los contadores vuelven a empezar
    mon.tick(t0 + 120, {k_rt: peer(500, 100, hs=t0 + 100), k_ph: peer(50, 70, hs=t0), k_gb: peer(110, 210, hs=t0)})
    # El router se cae (último handshake en t0+100); el aviso llega tras 5 minutos
    lost = {k_ph: peer(50, 70, hs=t0), k_gb: peer(110, 210, hs=t0)}
    assert mon.tick(t0 + 400, {k_rt: peer(500, 100, online=False, hs=t0 + 100), **lost}) == []
    ev = mon.tick(t0 + 400 + 6 * 60, {k_rt: peer(500, 100, online=False, hs=t0 + 100), **lost})
    assert [(e.kind, e.device_name, e.tenant_name) for e in ev] == [("device_offline", "MikroTik", "Acme")]
    assert mon.tick(t0 + 400 + 7 * 60, {k_rt: peer(500, 100, online=False, hs=t0 + 100), **lost}) == []  # una sola vez
    ev = mon.tick(t0 + 2000, {k_rt: peer(800, 400, hs=t0 + 1990, endpoint="203.0.113.99:1234"), **lost})
    assert [e.kind for e in ev] == ["device_online"] and ev[0].downtime == 2000 - 280
    # El iPhone (sin vigilar) se desconecta: se registra, pero no avisa
    assert mon.tick(t0 + 4000, {k_rt: peer(800, 400, hs=t0 + 3990), k_ph: peer(50, 70, online=False, hs=t0 + 3900)}) == []
    assert mon.tick(t0 + 5000, {k_rt: peer(800, 400, hs=t0 + 4990), k_ph: peer(50, 70, online=False, hs=t0 + 3900)}) == []

    tr = admin.get(f"/api/history/traffic?tenant_id={a['id']}&range=24h").json()
    assert tr["total"] == {"rx": 2000 + 500 + 300 + 50, "tx": 4000 + 100 + 300 + 70}
    assert len(tr["buckets"]) == 24 and tr["devices"][0]["name"] == "MikroTik"
    assert admin.get(f"/api/history/traffic?device_id={gb['id']}&range=7d").json()["total"] == {"rx": 100, "tx": 200}
    plat = admin.get("/api/history/traffic?range=30d").json()
    assert len(plat["buckets"]) == 30 and [t["name"] for t in plat["tenants"]] == ["Acme", "Globex"]
    assert len(admin.get("/api/history/traffic?range=12m").json()["buckets"]) == 12
    assert admin.get("/api/history/traffic?range=1y").status_code == 422

    evs = admin.get(f"/api/history/events?tenant_id={a['id']}").json()["events"]
    kinds = [(e["device"], e["kind"]) for e in evs]
    assert kinds == [("iPhone", "offline"), ("MikroTik", "online"), ("MikroTik", "offline"),
                     ("iPhone", "online"), ("MikroTik", "online")]
    assert evs[1]["endpoint"] == "203.0.113.99" and evs[2]["ts"] == int(t0 + 100 + 180)

    # Un cliente sólo ve lo suyo
    admin.patch(f"/api/admin/tenants/{b['id']}", json={"password": "Temporal1"}, headers=H)
    with TestClient(admin.app) as cb:
        cb.post("/api/auth/login", json={"username": "globex", "password": "Temporal1"}, headers=H)
        cb.post("/api/me/password", json={"current": "Temporal1", "new": "Globex222"}, headers=H)
        mine = cb.get(f"/api/history/traffic?tenant_id={a['id']}").json()
        assert mine["total"] == {"rx": 100, "tx": 200} and mine["tenants"] == []
        assert cb.get(f"/api/history/traffic?device_id={rt['id']}").status_code == 404
        assert {e["device"] for e in cb.get("/api/history/events").json()["events"]} <= {"PC Globex"}

    # Borrar un dispositivo conserva su historial en el cliente
    admin.delete(f"/api/devices/{rt['id']}", headers=H)
    tr = admin.get(f"/api/history/traffic?tenant_id={a['id']}").json()
    assert tr["devices"][0]["name"] == "Dispositivo eliminado" and tr["total"]["rx"] == 2850


def test_interface_down_is_not_an_outage(admin):
    mon = admin.app.state.monitor
    a = mk(admin, "acme")
    admin.post("/api/devices", json={"name": "Router", "tenant_id": a["id"], "kind": "router",
                                     "lan_networks": ["192.168.88.0/24"]}, headers=H)
    assert mon.tick() == []  # sin wg0 (pruebas): no hay lectura y nadie aparece caído


def test_dns_history(admin):
    from app.dnsfilter import TenantStats

    mon = admin.app.state.monitor
    a = mk(admin, "acme")
    st = TenantStats()
    for i in range(10):
        st.record(i % 3 == 0, "ads.example.com" if i % 2 else "tracker.example.net", "10.252.1.2")
    mon.dns.stats[a["id"]] = st
    mon.store_dns(mon.drain_dns())
    assert mon.drain_dns() == {}  # ya recogido
    st.record(True, "ads.example.com", "10.252.1.2")
    mon.store_dns(mon.drain_dns())
    r = admin.get(f"/api/history/dns?tenant_id={a['id']}&range=24h").json()
    assert r["total"] == {"queries": 11, "blocked": 5}
    assert r["top"][0] == {"domain": "tracker.example.net", "count": 2} or r["top"][0]["count"] >= 2
    assert sum(x["count"] for x in r["top"]) == 5
    assert admin.get(f"/api/history/dns?tenant_id={a['id']}&range=7d").json()["total"]["blocked"] == 5

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import domains, sysmon
from app.db import Database
from app.main import create_app

H = {"X-WGP": "1"}


class FakeProc:
    def __init__(self, path):
        self.p = path
        (path / "net").mkdir(parents=True)
        (path / "net" / "route").write_text("Iface\tDestination\tGateway\nens3\t00000000\t0101A8C0\nens3\t0001A8C0\t00000000\n")
        (path / "loadavg").write_text("0.52 0.40 0.31 1/123 4567\n")
        (path / "uptime").write_text("93784.12 300000.00\n")
        (path / "cpuinfo").write_text("processor\t: 0\nmodel name\t: AMD EPYC 7763\n")
        self.set(busy=0, idle=0, rx=0, tx=0, avail=6)

    def set(self, busy, idle, rx, tx, avail=6, swap_free=1):
        # cpu: user nice system idle iowait irq softirq steal
        (self.p / "stat").write_text(f"cpu  {busy} 0 0 {idle} 0 0 0 0 0 0\ncpu0 1 1 1 1\n")
        (self.p / "meminfo").write_text(f"MemTotal: {8 * 1024 * 1024} kB\nMemFree: 100 kB\nMemAvailable: {avail * 1024 * 1024} kB\n"
                                        f"SwapTotal: {2 * 1024 * 1024} kB\nSwapFree: {swap_free * 1024 * 1024} kB\n")
        (self.p / "net" / "dev").write_text(
            "Inter-|   Receive  |  Transmit\n face |bytes packets|bytes\n"
            f"    lo: 999 0 0 0 0 0 0 0 999 0 0 0 0 0 0 0\n"
            f"  ens3: {rx} 0 0 0 0 0 0 0 {tx} 0 0 0 0 0 0 0\n"
            f"   wg0: 5 0 0 0 0 0 0 0 5 0 0 0 0 0 0 0\n")


def make(tmp_path, notify=None):
    db = Database(tmp_path / "panel.db")
    db.init("admin", "admin", lambda: ("k", "p"))
    proc = FakeProc(tmp_path / "proc")
    return sysmon.Sysmon(db, tmp_path, notify, proc=str(tmp_path / "proc")), proc


def test_sampling_and_history(tmp_path):
    m, proc = make(tmp_path)
    t0 = 1_800_000_000 // 3600 * 3600          # en punto
    assert m.sample(t0) is None                # la primera sólo fija la referencia
    proc.set(busy=250, idle=750, rx=10_000_000, tx=2_000_000, avail=2)
    cur = m.sample(t0 + 10)
    assert cur["cpu"] == 25.0 and cur["mem"] == 75.0 and cur["swap"] == 50.0 and cur["iface"] == "ens3"
    assert cur["rx"] == 1_000_000 and cur["tx"] == 200_000 and cur["load1"] == 0.52
    live = m.live()
    assert live["ready"] and live["cores"] >= 1 and live["model"] == "AMD EPYC 7763" and live["uptime"] == 93784
    assert live["net"] == {"iface": "ens3", "rx": 1_000_000, "tx": 200_000} and 0 < live["disk"]["pct"] <= 100
    # contadores reiniciados (reinicio de la interfaz): nunca negativo
    proc.set(busy=500, idle=1500, rx=0, tx=0, avail=2)
    assert m.sample(t0 + 20)["rx"] == 0
    # paso de minuto -> fila por minuto con la media; y resumen horario
    proc.set(busy=1500, idle=1500, rx=0, tx=0, avail=2)
    m.sample(t0 + 70)
    with m.db.conn() as c:
        row = c.execute("SELECT * FROM sys_minute").fetchone()
        assert row["ts"] == t0 and row["cpu"] == 25.0 and row["rx"] == 500_000
        assert c.execute("SELECT cpu FROM sys_hourly WHERE hour = ?", (t0,)).fetchone()["cpu"] == 25.0
    h = m.history("1h", now=t0 + 70)
    assert len(h["points"]) == 60 and h["step"] == 60
    assert h["points"][-2]["t"] == t0 and h["points"][-2]["cpu"] == 25.0 and h["points"][-1]["cpu"] is None
    d = m.history("7d", now=t0 + 70)
    assert len(d["points"]) == 168 and d["points"][-1]["cpu_max"] == 25.0
    assert len(m.history("30d", now=t0)["points"]) == 180 and len(m.history("24h", now=t0)["points"]) == 288
    with pytest.raises(Exception):
        m.history("2y")


def test_alerts(tmp_path):
    sent = []
    m, _ = make(tmp_path, lambda title, body: sent.append(title))
    t0 = 1_800_000_000
    with m.db.conn() as c:
        for i in range(15):
            c.execute("INSERT INTO sys_minute (ts, cpu, mem, swap, disk, load1, rx, tx) VALUES (?, ?, ?, 0, ?, 1, 0, 0)",
                      (t0 + 60 * i, 95, 50 if i < 14 else 92, 91))
    assert m.check_alerts() == ["⚠️ Disco del servidor al 91 %", "⚠️ CPU del servidor al 95 %"]   # la memoria sólo 1 min alta
    assert m.check_alerts() == []                                                               # sin repetir
    assert m.alerts() == {"cpu": True, "disk": True}
    with m.db.conn() as c:
        c.execute("UPDATE sys_minute SET disk = 80, cpu = 20")
    assert m.check_alerts() == ["🟢 Disco del servidor normal (80 %)", "🟢 CPU del servidor normal (20 %)"]
    assert m.alerts() == {} and len(sent) == 4


def test_api(tmp_path, monkeypatch):
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
        m = c.app.state.sysmon
        FakeProc(tmp_path / "proc")
        m.proc = str(tmp_path / "proc")
        m._prev = None
        m.sample(1_800_000_000)
        m.sample(1_800_000_010)
        (tmp_path / "wireguard" / "wgp").mkdir(parents=True, exist_ok=True)
        (tmp_path / "wireguard" / "wgp" / "version.json").write_text('{"version": "2.12.0", "hostname": "vps1", "os": "Ubuntu 24.04"}')
        live = c.get("/api/admin/server/live").json()
        assert live["ready"] and live["hostname"] == "vps1" and live["os"] == "Ubuntu 24.04"
        assert c.get("/api/admin/server/history?range=7d").json()["range"] == "7d"
        assert c.get("/api/admin/server/history?range=x").status_code == 422
        assert c.get("/api/admin/overview").json()["system"]["ready"]
        prefs = c.get("/api/alerts").json()
        assert prefs["prefs"]["server"] is True
        c.post("/api/admin/tenants", json={"name": "Acme", "username": "acme", "password": "Password1"}, headers=H)
        c.post("/api/auth/logout", headers=H)
        c.post("/api/auth/login", json={"username": "acme", "password": "Password1"}, headers=H)
        assert c.get("/api/admin/server/live").status_code == 403

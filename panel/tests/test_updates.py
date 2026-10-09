from __future__ import annotations

import datetime as dt
import json
import time

import pytest
from fastapi.testclient import TestClient

from app import domains, updates
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
        c.wgp = tmp_path / "wireguard" / "wgp"
        c.wgp.mkdir(parents=True, exist_ok=True)
        yield c


def host_files(wgp, version="2.10.0", updater=True):
    info = {"version": version, "commit": "abc1234", "updated_at": 1700000000, "branch": "main"}
    if updater:
        info["updater"] = 1
    (wgp / "version.json").write_text(json.dumps(info))


def test_versions():
    assert updates.newer("2.11.0", "2.10.0") and updates.newer("2.10.1", "2.10.0") and updates.newer("10.0.0", "9.9.9")
    assert not updates.newer("2.10.0", "2.10.0") and not updates.newer("2.9.9", "2.10.0") and not updates.newer(None, "2.10.0")
    assert updates.VERSION_RE.search('#!/bin/bash\nreadonly VERSION="2.11.0"\n').group(1) == "2.11.0"


def test_update_from_panel(admin, monkeypatch):
    upd = admin.app.state.updates
    monkeypatch.setattr(upd, "fetch_remote", lambda: "2.11.0")
    # Sin version.json (instalación anterior): no se puede pedir, hay que actualizar una vez a mano
    v = admin.get("/api/admin/update").json()
    assert v["ready"] is False and v["current"] is None
    assert admin.post("/api/admin/update/run", headers=H).status_code == 409
    host_files(admin.wgp)
    v = admin.post("/api/admin/update/check", headers=H).json()
    assert v["ready"] and v["current"] == "2.10.0" and v["latest"] == "2.11.0" and v["available"] and v["commit"] == "abc1234"

    v = admin.post("/api/admin/update/run", headers=H).json()
    req = json.loads((admin.wgp / "update.request").read_text())
    assert req["reason"] == "manual" and v["status"]["state"] == "queued"
    assert admin.post("/api/admin/update/run", headers=H).status_code == 409          # ya en marcha
    # El host la recoge
    (admin.wgp / "update.status").write_text(json.dumps({"state": "running", "started_at": req["at"] + 1}))
    assert admin.get("/api/admin/update").json()["status"]["state"] == "running"
    assert admin.post("/api/admin/update/run", headers=H).status_code == 409
    # …y termina: versión nueva, registro y un único aviso
    (admin.wgp / "update.log").write_text("\x1b[1m== inicio\x1b[0m\n" + "línea\n" * 500 + "fin\n")
    (admin.wgp / "update.status").write_text(json.dumps({"state": "done", "started_at": req["at"] + 1,
                                                          "finished_at": req["at"] + 60, "exit_code": 0, "version": "2.11.0"}))
    host_files(admin.wgp, "2.11.0")
    sent = []
    upd.notify = lambda title, body: sent.append(title)
    v = admin.get("/api/admin/update").json()
    assert v["status"]["state"] == "done" and v["current"] == "2.11.0" and not v["available"]
    assert v["log"].endswith("fin") and "\x1b" not in v["log"] and len(v["log"].splitlines()) == 200
    upd.tick()
    upd.tick()
    assert sent == ["✅ Servidor actualizado a v2.11.0"]
    # Se puede volver a pedir
    assert admin.post("/api/admin/update/run", headers=H).status_code == 200
    # Sólo administradores
    admin.post("/api/admin/tenants", json={"name": "Acme", "username": "acme", "password": "Password1"}, headers=H)
    admin.post("/api/auth/logout", headers=H)
    admin.post("/api/auth/login", json={"username": "acme", "password": "Password1"}, headers=H)
    assert admin.get("/api/admin/update").status_code == 403


def test_stale_states(admin):
    upd = admin.app.state.updates
    host_files(admin.wgp)
    upd.request("manual")
    now = time.time()
    assert upd.status(now + 10)["state"] == "queued"
    assert upd.status(now + updates.QUEUE_TIMEOUT + 5)["state"] == "stuck"       # el host no la recogió
    (admin.wgp / "update.status").write_text(json.dumps({"state": "running", "started_at": int(now) + 1}))
    assert upd.status(now + updates.RUN_TIMEOUT + 60)["state"] == "lost"


def test_auto_update(admin, monkeypatch):
    upd = admin.app.state.updates
    host_files(admin.wgp)
    remote = {"v": "2.10.0"}
    checks = []
    monkeypatch.setattr(upd, "fetch_remote", lambda: checks.append(1) or remote["v"])
    assert admin.put("/api/admin/update/auto", json={"enabled": True, "day": "7", "hour": 3}, headers=H).status_code == 422
    assert admin.put("/api/admin/update/auto", json={"enabled": True, "day": "daily", "hour": 25}, headers=H).status_code == 422
    v = admin.put("/api/admin/update/auto", json={"enabled": True, "day": "2", "hour": 3}, headers=H).json()
    assert v["auto"] == {"enabled": True, "day": "2", "hour": 3}

    wed_early = dt.datetime(2026, 10, 7, 2, 30)     # miércoles = 2
    wed = dt.datetime(2026, 10, 7, 3, 1)
    thu = dt.datetime(2026, 10, 8, 3, 1)
    assert not upd.due(wed_early) and upd.due(wed) and not upd.due(thu)
    assert upd.tick(wed) == "up-to-date" and not (admin.wgp / "update.request").exists()
    assert not upd.due(dt.datetime(2026, 10, 7, 9, 0))                 # una vez por día
    remote["v"] = "2.11.0"
    nxt = dt.datetime(2026, 10, 14, 4, 0)
    assert upd.tick(nxt) == "requested"
    assert json.loads((admin.wgp / "update.request").read_text())["reason"] == "automática"

    admin.put("/api/admin/update/auto", json={"enabled": True, "day": "daily", "hour": 0}, headers=H)
    assert upd.due(thu)
    admin.put("/api/admin/update/auto", json={"enabled": False, "day": "daily", "hour": 0}, headers=H)
    assert not upd.due(dt.datetime(2026, 10, 9, 5, 0))
    # Sin actualizador instalado tampoco
    admin.put("/api/admin/update/auto", json={"enabled": True, "day": "daily", "hour": 0}, headers=H)
    host_files(admin.wgp, updater=False)
    assert not upd.due(dt.datetime(2026, 10, 10, 5, 0))


def test_check_failure_keeps_last(admin, monkeypatch):
    upd = admin.app.state.updates
    host_files(admin.wgp)
    monkeypatch.setattr(upd, "fetch_remote", lambda: "2.11.0")
    upd.check()

    def boom():
        raise OSError("sin red")
    monkeypatch.setattr(upd, "fetch_remote", boom)
    v = admin.post("/api/admin/update/check", headers=H).json()
    assert v["latest"] == "2.11.0" and v["available"] and "sin red" in v["check_error"]


def test_failed_update_notifies(admin):
    upd = admin.app.state.updates
    host_files(admin.wgp)
    sent = []
    upd.notify = lambda title, body: sent.append((title, body))
    (admin.wgp / "update.status").write_text(json.dumps({"state": "failed", "started_at": 1, "finished_at": 2, "exit_code": 1}))
    upd.tick()
    assert sent and "fallado" in sent[0][0] and "código 1" in sent[0][1]

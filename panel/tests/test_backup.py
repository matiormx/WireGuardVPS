from __future__ import annotations

import datetime as dt
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app import backup
from app.config import load_settings
from app.main import create_app

H = {"X-WGP": "1"}
PASS = "frase de paso larga"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("WG_CONF_DIR", str(tmp_path / "wireguard"))
    monkeypatch.setenv("WG_ENDPOINT", "203.0.113.10")
    monkeypatch.setenv("SESSION_SECRET", "x")
    monkeypatch.setenv("DNS_ENABLED", "false")
    monkeypatch.setenv("CADDY_ADMIN", "")
    monkeypatch.setattr("app.wg.WireGuardManager.host_networks", lambda self: [])
    return tmp_path


@pytest.fixture()
def admin(env):
    with TestClient(create_app()) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": "admin"}, headers=H)
        c.post("/api/me/password", json={"current": "admin", "new": "AdminPass1"}, headers=H)
        yield c


def test_crypto_roundtrip():
    blob = backup.encrypt(b"hola", PASS)
    assert blob.startswith(backup.MAGIC) and b"hola" not in blob
    assert backup.decrypt(blob, PASS) == b"hola"
    with pytest.raises(backup.BackupError, match="incorrecta"):
        backup.decrypt(blob, "otra frase cualquiera")
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(backup.BackupError):
        backup.decrypt(tampered, PASS)
    with pytest.raises(backup.BackupError, match="No es una copia"):
        backup.decrypt(b"basura" * 20, PASS)


def test_api_backup_and_restore(admin, env, monkeypatch):
    t = admin.post("/api/admin/tenants", json={"name": "Acme", "username": "acme", "password": "Password1"}, headers=H).json()
    admin.post("/api/devices", json={"name": "Portátil", "tenant_id": t["id"]}, headers=H)
    admin.put("/api/admin/wg-settings", json={"endpoint": "wg.ejemplo.com"}, headers=H)

    # Sin frase de paso no hay copias
    assert admin.post("/api/admin/backup/run", headers=H).status_code == 409
    assert admin.put("/api/admin/backup", json={"enabled": True}, headers=H).status_code == 422
    assert admin.put("/api/admin/backup", json={"passphrase": "corta"}, headers=H).status_code == 422
    st = admin.put("/api/admin/backup", json={"passphrase": PASS, "enabled": True, "hour": 4, "keep": 2}, headers=H).json()
    assert st["enabled"] and st["has_passphrase"] and st["hour"] == 4 and "passphrase" not in str(st).replace("has_passphrase", "")

    names = []
    _Clock.ticks = [dt.datetime(2026, 1, 1, 10, 0, i, tzinfo=dt.timezone.utc) for i in range(3)]
    monkeypatch.setattr(backup.dt, "datetime", _Clock)
    for _ in range(3):
        r = admin.post("/api/admin/backup/run", headers=H).json()
        names.append(r["result"]["name"])
        assert r["result"]["ok"] and r["result"]["s3"] is None
    monkeypatch.undo()
    listed = [b["name"] for b in admin.get("/api/admin/backup").json()["backups"]]
    assert listed == names[:0:-1]  # retención: las 2 más recientes

    blob = admin.get(f"/api/admin/backups/{names[-1]}").content
    assert admin.get("/api/admin/backups/..%2Fpanel.db").status_code == 404
    assert admin.get("/api/admin/backups/wgp-20990101-000000.wgpb").status_code == 404

    meta, db_bytes = backup.open_archive(blob, PASS)
    assert meta["network"]["WG_SUBNET"] == "10.252.0.0/16"
    info = backup.summarize(db_bytes)
    assert info == {"tenants": 1, "devices": 1, "endpoint": "wg.ejemplo.com", "main_domain": ""}

    # Restaurar en otro servidor (directorio de datos nuevo)
    monkeypatch.setenv("DATA_DIR", str(env / "nuevo"))
    settings = load_settings()
    r = backup.restore(settings, blob, PASS)
    assert r["tenants"] == 1 and r["devices"] == 1
    c = sqlite3.connect(env / "nuevo" / "panel.db")
    assert c.execute("SELECT name FROM tenants").fetchone()[0] == "Acme"
    c.close()
    with TestClient(create_app()) as c2:
        assert c2.post("/api/auth/login", json={"username": "admin", "password": "AdminPass1"}, headers=H).status_code == 200
        assert c2.get("/api/admin/wg-settings").json()["effective"] == "wg.ejemplo.com"
    # Restaurar encima guarda la base anterior
    backup.restore(settings, blob, PASS)
    assert list((env / "nuevo").glob("panel.db.pre-restore-*"))

    # Red distinta: se rechaza salvo --force
    monkeypatch.setenv("WG_SUBNET", "10.99.0.0/16")
    monkeypatch.setenv("WG_SERVER_ADDRESS", "10.99.0.1/16")
    with pytest.raises(backup.BackupError, match="WG_SUBNET=10.252.0.0/16"):
        backup.restore(load_settings(), blob, PASS)
    with pytest.raises(backup.BackupError, match="incorrecta"):
        backup.restore(load_settings(), blob, "frase equivocada!!")

    assert admin.delete(f"/api/admin/backups/{names[-1]}", headers=H).status_code == 200


class _Clock(dt.datetime):
    ticks: list = []

    @classmethod
    def now(cls, tz=None):
        return cls.ticks.pop(0)


def test_schedule(admin):
    b = admin.app.state.backups
    noon = dt.datetime(2026, 3, 1, 12, 0)
    assert not b.due(noon)  # desactivadas
    admin.put("/api/admin/backup", json={"passphrase": PASS, "enabled": True, "hour": 3}, headers=H)
    assert b.due(noon)
    assert not b.due(dt.datetime(2026, 3, 1, 2, 0))  # antes de la hora
    b._record({"at": int(noon.timestamp()), "name": "x", "size": 1, "ok": True, "error": None, "s3": None})
    assert not b.due(noon.replace(hour=23))  # ya hecha hoy
    assert b.due(dt.datetime(2026, 3, 2, 3, 5))  # al día siguiente


def test_s3_upload(admin, monkeypatch):
    moto_server = pytest.importorskip("moto.server")
    import boto3

    srv = moto_server.ThreadedMotoServer(ip_address="127.0.0.1", port=0, verbose=False)
    srv.start()
    try:
        host, port = srv.get_host_and_port()
        url = f"http://{host}:{port}"
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            monkeypatch.delenv(k, raising=False)
        s3 = boto3.client("s3", endpoint_url=url, region_name="us-east-1", aws_access_key_id="AK", aws_secret_access_key="SK")
        s3.create_bucket(Bucket="copias")
        cfg = {"s3_endpoint": url, "s3_bucket": "copias", "s3_region": "us-east-1", "s3_prefix": "wg/",
               "s3_access_key": "AK", "s3_secret_key": "SK", "passphrase": PASS}
        assert admin.post("/api/admin/backup/test-s3", json={**cfg, "s3_bucket": "no-existe"}, headers=H).status_code == 409
        assert admin.post("/api/admin/backup/test-s3", json=cfg, headers=H).json() == {"ok": True}
        assert admin.put("/api/admin/backup", json={**cfg, "s3_bucket": "Mal Nombre"}, headers=H).status_code == 422
        st = admin.put("/api/admin/backup", json=cfg, headers=H).json()
        assert st["s3"]["configured"] and st["s3"]["secret_set"] and "SK" not in str(st)
        # Cambiar otros campos sin reenviar el secreto lo conserva
        admin.put("/api/admin/backup", json={"s3_prefix": "wg/"}, headers=H)
        r = admin.post("/api/admin/backup/run", headers=H).json()["result"]
        assert r["ok"] and r["s3"] == f"wg/{r['name']}"
        body = s3.get_object(Bucket="copias", Key=r["s3"])["Body"].read()
        assert backup.open_archive(body, PASS)[0]["format"] == 1
        keys = [o["Key"] for o in s3.list_objects_v2(Bucket="copias")["Contents"]]
        assert keys == [r["s3"]]  # el objeto de prueba se borró
        # Fallo de subida: la copia local se crea igualmente y se informa
        admin.put("/api/admin/backup", json={"s3_bucket": "borrado"}, headers=H)
        r = admin.post("/api/admin/backup/run", headers=H).json()["result"]
        assert not r["ok"] and "falló la subida" in r["error"] and r["name"]
        assert admin.put("/api/admin/backup", json={"clear_s3": True}, headers=H).json()["s3"]["configured"] is False
    finally:
        srv.stop()


def test_s3_signature_matches_botocore():
    botocore = pytest.importorskip("botocore")
    from botocore.auth import S3SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    cfg = {"s3_endpoint": "https://abc123.r2.cloudflarestorage.com", "s3_bucket": "mis-copias", "s3_region": "auto",
           "s3_access_key": "AKIDEXAMPLE", "s3_secret_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
    now = dt.datetime(2026, 10, 9, 8, 30, 0, tzinfo=dt.timezone.utc)
    for method, key, data in (("PUT", "wg/wgp-20261009-083000.wgpb", b"x" * 100), ("DELETE", "wg/.wgp test", b"")):
        url, headers = backup.s3_sign(cfg, method, key, data, now)
        mine = headers.pop("authorization").rsplit("Signature=", 1)[1]
        req = AWSRequest(method=method, url=url, data=data, headers=headers)
        auth = S3SigV4Auth(Credentials(cfg["s3_access_key"], cfg["s3_secret_key"]), "s3", "auto")
        req.context["timestamp"] = headers["x-amz-date"]
        sts = auth.string_to_sign(req, auth.canonical_request(req))
        assert mine == auth.signature(sts, req), botocore.__version__

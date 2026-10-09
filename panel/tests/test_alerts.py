from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi.testclient import TestClient

from app import alerts
from app.main import create_app
from app.monitor import Event

H = {"X-WGP": "1"}


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


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


@pytest.fixture()
def sent(admin, monkeypatch):
    """Captura los envíos reales (Telegram/email/push) sin salir a la red."""
    out = []
    n = admin.app.state.notifier

    def fake_telegram(method, params, token=None, timeout=15):
        if method == "getMe":
            if token and token.startswith("999"):
                raise RuntimeError("Unauthorized")
            return {"username": "wgcloud_bot"}
        out.append(("telegram", method, params))
        return {}

    monkeypatch.setattr(n, "telegram", fake_telegram)
    monkeypatch.setattr(n, "email", lambda to, subject, body: out.append(("email", to, subject, body)))
    monkeypatch.setattr(n, "push", lambda sub, msg: out.append(("push", sub["endpoint"], msg)))
    monkeypatch.setattr(n, "start_telegram", lambda: None)

    class Sync:  # entrega síncrona para poder comprobarla
        def submit(self, fn, *a):
            fn(*a)
    monkeypatch.setattr(n, "pool", Sync())
    return out


def test_web_push_encryption_and_vapid():
    http_ece = pytest.importorskip("http_ece")
    ua = ec.generate_private_key(ec.SECP256R1())
    ua_pub = ua.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    auth = b"0123456789abcdef"
    body = alerts.encrypt_push(b'{"title":"hola"}', b64u(ua_pub), b64u(auth))
    assert http_ece.decrypt(body, private_key=ua, auth_secret=auth, version="aes128gcm") == b'{"title":"hola"}'

    key = ec.generate_private_key(ec.SECP256R1())
    pub = b64u(key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
    header = alerts.vapid_header("https://fcm.googleapis.com/fcm/send/abc", key, pub, "mailto:a@b.com")
    token = header.split("t=")[1].split(",")[0]
    head, claims, sig = token.split(".")
    claims = json.loads(alerts.b64u_decode(claims))
    assert claims["aud"] == "https://fcm.googleapis.com" and claims["exp"] > time.time()
    raw = alerts.b64u_decode(sig)
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    key.public_key().verify(der, f"{head}.{token.split('.')[1]}".encode(), ec.ECDSA(hashes.SHA256()))
    assert header.endswith(f"k={pub}")

    assert alerts.push_endpoint_ok("https://fcm.googleapis.com/fcm/send/x")
    assert alerts.push_endpoint_ok("https://web.push.apple.com/QGuQyavXutnMH")
    assert not alerts.push_endpoint_ok("http://fcm.googleapis.com/x")
    assert not alerts.push_endpoint_ok("https://169.254.169.254/latest")
    assert not alerts.push_endpoint_ok("https://evil-googleapis.com/x")


def test_config_channels_and_delivery(admin, sent):
    st = admin.get("/api/alerts").json()
    assert st["available"]["telegram"] is False and st["prefs"] == {"devices_all": True, "backup": True, "billing": True}
    assert len(alerts.b64u_decode(st["available"]["push_key"])) == 65
    assert admin.post("/api/alerts/telegram/link", headers=H).status_code == 409
    assert admin.put("/api/admin/alerts-config", json={"telegram_token": "malo"}, headers=H).status_code == 422
    assert admin.put("/api/admin/alerts-config", json={"telegram_token": "99999:" + "A" * 35}, headers=H).status_code == 409
    cfg = admin.put("/api/admin/alerts-config", json={"telegram_token": "123456:" + "A" * 35, "smtp_host": "smtp.x.com",
                                                     "smtp_from": "Avisos <avisos@x.com>", "smtp_password": "secreto",
                                                     "delay_min": 10}, headers=H).json()
    assert cfg["telegram"] == {"configured": True, "bot": "wgcloud_bot"} and cfg["smtp"]["password_set"]
    assert "secreto" not in json.dumps(cfg) and cfg["delay_min"] == 10
    assert admin.put("/api/admin/alerts-config", json={"smtp_host": "a\r\nb"}, headers=H).status_code == 422

    # Telegram: enlace + /start desde el chat
    link = admin.post("/api/alerts/telegram/link", headers=H).json()
    code = link["url"].split("start=")[1]
    assert link["url"].startswith("https://t.me/wgcloud_bot?start=")
    n = admin.app.state.notifier
    n.handle_update({"message": {"chat": {"id": 555, "type": "private", "first_name": "Ana"}, "text": f"/start {code}"}})
    n.handle_update({"message": {"chat": {"id": 666, "type": "private"}, "text": f"/start {code}"}})  # código ya usado
    assert "activados" in sent[-2][2]["text"] and "Conectar Telegram" in sent[-1][2]["text"]
    n.handle_update({"message": {"chat": {"id": -1, "type": "group"}, "text": "/start x"}})  # grupos: ignorado

    assert admin.post("/api/alerts/email", json={"email": "no-es-email"}, headers=H).status_code == 422
    admin.post("/api/alerts/email", json={"email": "Ana@Example.com"}, headers=H)
    sub = {"endpoint": "https://fcm.googleapis.com/fcm/send/abc",
           "p256dh": b64u(ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
               serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)),
           "auth": b64u(b"0123456789abcdef"), "label": "iPhone"}
    assert admin.post("/api/alerts/push", json={**sub, "endpoint": "https://10.0.0.1/x"}, headers=H).status_code == 422
    st = admin.post("/api/alerts/push", json=sub, headers=H).json()
    assert [(c["kind"], c["label"]) for c in st["channels"]] == [("telegram", "Ana"), ("email", "Ana@Example.com"), ("push", "iPhone")]

    sent.clear()
    tg = st["channels"][0]["id"]
    assert admin.post(f"/api/alerts/channels/{tg}/test", headers=H).json() == {"ok": True}
    assert sent[0][2]["chat_id"] == "555" and "prueba" in sent[0][2]["text"]

    # Evento del monitor -> cliente, admin (todos los clientes); prefs respetadas
    t = admin.post("/api/admin/tenants", json={"name": "Acme", "username": "acme", "password": "Password1"}, headers=H).json()
    sent.clear()
    ev = Event("device_offline", t["id"], "Acme", 7, "MikroTik <oficina>", "router", None, int(time.time()),
               extra={"since": int(time.time()) - 400})
    n.on_monitor_events([ev])
    assert {x[0] for x in sent} == {"telegram", "email", "push"}
    tgmsg = next(x for x in sent if x[0] == "telegram")[2]["text"]
    assert "MikroTik &lt;oficina&gt; desconectado" in tgmsg and "Router de Acme" in tgmsg
    assert next(x for x in sent if x[0] == "push")[2]["url"] == "/#/activity"
    sent.clear()
    admin.put("/api/alerts/prefs", json={"devices_all": False}, headers=H)
    n.on_monitor_events([ev])
    assert sent == []
    n.on_backup_failed("Disco lleno")
    assert any("Copia de seguridad fallida" in x[2] for x in sent if x[0] == "email")

    # Canal con errores: se registra; una suscripción push caducada se elimina
    def boom(sub, msg):
        raise alerts.PushGone("gone")
    n.push = boom
    push_id = [c for c in admin.get("/api/alerts").json()["channels"] if c["kind"] == "push"][0]["id"]
    assert admin.post(f"/api/alerts/channels/{push_id}/test", headers=H).status_code == 409
    assert all(c["kind"] != "push" for c in admin.get("/api/alerts").json()["channels"])
    n.handle_update({"message": {"chat": {"id": 555, "type": "private"}, "text": "/stop"}})
    assert all(c["kind"] != "telegram" for c in admin.get("/api/alerts").json()["channels"])


def test_channels_are_private(admin, sent):
    admin.put("/api/admin/alerts-config", json={"smtp_host": "smtp.x.com", "smtp_from": "avisos@x.com"}, headers=H)
    st = admin.post("/api/alerts/email", json={"email": "admin@x.com"}, headers=H).json()
    cid = st["channels"][0]["id"]
    t = admin.post("/api/admin/tenants", json={"name": "Acme", "username": "acme", "password": "Password1"}, headers=H).json()
    admin.patch(f"/api/admin/tenants/{t['id']}", json={"password": "Temporal1"}, headers=H)
    with TestClient(admin.app) as ca:
        ca.post("/api/auth/login", json={"username": "acme", "password": "Temporal1"}, headers=H)
        ca.post("/api/me/password", json={"current": "Temporal1", "new": "Acme22222"}, headers=H)
        mine = ca.get("/api/alerts").json()
        assert mine["channels"] == [] and mine["prefs"] == {"devices": True}
        assert ca.delete(f"/api/alerts/channels/{cid}", headers=H).status_code == 404
        assert ca.post(f"/api/alerts/channels/{cid}/test", headers=H).status_code == 404
        assert ca.get("/api/admin/alerts-config").status_code == 403
        ca.post("/api/alerts/email", json={"email": "acme@x.com"}, headers=H)
        for i in range(9):
            ca.post("/api/alerts/email", json={"email": f"a{i}@x.com"}, headers=H)
        assert ca.post("/api/alerts/email", json={"email": "extra@x.com"}, headers=H).status_code == 409
    admin.delete(f"/api/admin/tenants/{t['id']}", headers=H)
    with admin.app.state.db.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM alert_channels WHERE role = 'tenant'").fetchone()[0] == 0


def test_email_smtp(admin, monkeypatch):
    calls = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None, context=None):
            calls.append(("connect", host, port))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context=None):
            calls.append(("starttls",))

        def login(self, user, password):
            calls.append(("login", user, password))

        def send_message(self, msg):
            calls.append(("send", msg["From"], msg["To"], msg["Subject"], msg.get_content()))

    monkeypatch.setattr(alerts.smtplib, "SMTP", FakeSMTP)
    admin.put("/api/admin/alerts-config", json={"smtp_host": "smtp.x.com", "smtp_port": 587, "smtp_user": "u",
                                               "smtp_password": "p", "smtp_from": "avisos@x.com"}, headers=H)
    admin.app.state.notifier.email("ana@x.com", "🔴 Router caído", "Detalle")
    assert calls[:3] == [("connect", "smtp.x.com", 587), ("starttls",), ("login", "u", "p")]
    send = calls[3]
    assert send[1] == "WireGuard Cloud <avisos@x.com>" and send[2] == "ana@x.com" and send[3] == "🔴 Router caído"
    assert "Detalle" in send[4]

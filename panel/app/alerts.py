"""Avisos: Telegram, email y notificaciones push (Web Push) para admin, clientes y usuarios.

Cada persona tiene sus canales (un chat de Telegram, direcciones de email y los
navegadores/móviles donde activó las notificaciones) y sus preferencias.
Eventos:
  * dispositivo vigilado desconectado / recuperado (monitor) -> su cliente, el
    usuario al que pertenece y, si quieren, los administradores;
  * copia de seguridad automática fallida -> administradores.

Telegram: un único bot de la plataforma (token en Ajustes). Cada persona lo
vincula con un enlace t.me/<bot>?start=<código>; el panel recibe el /start por
long polling (sin abrir puertos ni webhooks).

Web Push: cifrado RFC 8291 (aes128gcm) y VAPID RFC 8292 implementados con
`cryptography`, sin dependencias nuevas. Sólo se aceptan endpoints de los
servicios de push conocidos (evita que el servidor haga peticiones a destinos
arbitrarios).

Sin `from __future__ import annotations`: FastAPI evalúa las dependencias de `deps`.
"""
import base64
import concurrent.futures
import datetime as dt
import json
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from email.utils import formataddr, parseaddr

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import cfdns
from .db import Database, get_setting, set_setting

log = logging.getLogger("wgp.alerts")

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
TOKEN_RE = re.compile(r"^\d{5,15}:[A-Za-z0-9_-]{30,64}$")
PUSH_HOSTS = (".googleapis.com", ".push.services.mozilla.com", ".push.apple.com", ".notify.windows.com")
DEFAULT_PREFS = {
    "admin": {"devices_all": True, "backup": True, "billing": True, "server": True},
    "tenant": {"devices": True},
    "member": {"devices": True},
}
MAX_CHANNELS = 10
LINK_TTL = 15 * 60


# --------------------------------------------------------------------------- utilidades
def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def fmt_duration(seconds: int) -> str:
    m = max(1, round(seconds / 60))
    if m < 60:
        return f"{m} min"
    h, m = divmod(m, 60)
    if h < 48:
        return f"{h} h {m} min" if m else f"{h} h"
    return f"{h // 24} días"


def clock(ts: float) -> str:
    d = dt.datetime.fromtimestamp(ts)
    return d.strftime("%H:%M") if d.date() == dt.date.today() else d.strftime("%d/%m %H:%M")


# --------------------------------------------------------------------------- Web Push
def vapid_keys(c: sqlite3.Connection) -> tuple[ec.EllipticCurvePrivateKey, str]:
    """Claves VAPID de la plataforma (se generan la primera vez)."""
    raw = get_setting(c, "vapid_private")
    if raw:
        key = serialization.load_pem_private_key(raw.encode(), password=None)
    else:
        key = ec.generate_private_key(ec.SECP256R1())
        set_setting(c, "vapid_private", key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
    public = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return key, b64u(public)


def push_endpoint_ok(endpoint: str) -> bool:
    url = urllib.parse.urlsplit(endpoint)
    host = (url.hostname or "").lower()
    return url.scheme == "https" and any(host.endswith(h) or host == h[1:] for h in PUSH_HOSTS)


def encrypt_push(payload: bytes, p256dh: str, auth: str) -> bytes:
    """Cuerpo cifrado aes128gcm (RFC 8291) para una suscripción."""
    ua_public = b64u_decode(p256dh)
    auth_secret = b64u_decode(auth)
    ua_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    as_key = ec.generate_private_key(ec.SECP256R1())
    as_public = as_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    shared = as_key.exchange(ec.ECDH(), ua_key)
    ikm = HKDF(hashes.SHA256(), 32, auth_secret, b"WebPush: info\x00" + ua_public + as_public).derive(shared)
    salt = os.urandom(16)
    cek = HKDF(hashes.SHA256(), 16, salt, b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(hashes.SHA256(), 12, salt, b"Content-Encoding: nonce\x00").derive(ikm)
    ciphertext = AESGCM(cek).encrypt(nonce, payload + b"\x02", None)  # \x02: último registro
    return salt + (4096).to_bytes(4, "big") + bytes([len(as_public)]) + as_public + ciphertext


def vapid_header(endpoint: str, key: ec.EllipticCurvePrivateKey, public_b64: str, subject: str) -> str:
    url = urllib.parse.urlsplit(endpoint)
    claims = {"aud": f"{url.scheme}://{url.netloc}", "exp": int(time.time()) + 12 * 3600, "sub": subject}
    signing = f"{b64u(json.dumps({'typ': 'JWT', 'alg': 'ES256'}).encode())}.{b64u(json.dumps(claims).encode())}"
    r, s = decode_dss_signature(key.sign(signing.encode(), ec.ECDSA(hashes.SHA256())))
    token = f"{signing}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"
    return f"vapid t={token}, k={public_b64}"


# --------------------------------------------------------------------------- modelos API
class PrefsIn(BaseModel):
    devices: bool | None = None
    devices_all: bool | None = None
    backup: bool | None = None
    billing: bool | None = None
    server: bool | None = None


class EmailIn(BaseModel):
    email: str = Field(min_length=5, max_length=254)


class PushIn(BaseModel):
    endpoint: str = Field(min_length=10, max_length=1000)
    p256dh: str = Field(min_length=40, max_length=200)
    auth: str = Field(min_length=10, max_length=100)
    label: str = Field(default="", max_length=60)


class AlertsConfigIn(BaseModel):
    telegram_token: str | None = Field(default=None, max_length=100)  # "" = quitar
    smtp_host: str | None = Field(default=None, max_length=200)
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    smtp_security: str | None = Field(default=None, pattern="^(starttls|ssl|none)$")
    smtp_user: str | None = Field(default=None, max_length=200)
    smtp_password: str | None = Field(default=None, max_length=200)  # vacío = conservar
    smtp_from: str | None = Field(default=None, max_length=200)
    email_provider: str | None = Field(default=None, pattern="^(smtp|cloudflare)$")
    cf_from: str | None = Field(default=None, max_length=200)
    cf_token: str | None = Field(default=None, max_length=200)       # "" = usar el de Subdominios
    cf_account: str | None = Field(default=None, max_length=64)      # "" = deducirlo del dominio del remitente
    delay_min: int | None = Field(default=None, ge=1, le=120)


def email_provider(c: sqlite3.Connection) -> str:
    return get_setting(c, "email_provider") or "smtp"


def email_ready(c: sqlite3.Connection) -> bool:
    """¿Se pueden enviar emails? Por SMTP o por Cloudflare Email Service."""
    if email_provider(c) == "cloudflare":
        return bool(get_setting(c, "cfmail_from") and get_setting(c, "cfmail_account")
                    and (get_setting(c, "cfmail_token") or get_setting(c, "cf_token")))
    return bool(get_setting(c, "smtp_host") and get_setting(c, "smtp_from"))


def sender_address(c: sqlite3.Connection) -> str:
    return (get_setting(c, "cfmail_from") if email_provider(c) == "cloudflare" else get_setting(c, "smtp_from")) or ""


# --------------------------------------------------------------------------- motor
class Notifier:
    def __init__(self, database: Database, title: str = "WireGuard Cloud") -> None:
        self.db = database
        self.title = title   # nombre por defecto; el real es el de Ajustes › Marca (brand_name)
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=3, thread_name_prefix="alerts")
        self._tg_thread: threading.Thread | None = None
        self._tg_stop = threading.Event()
        self._tg_token: str | None = None
        self.opener = urllib.request.build_opener()  # Telegram / push: respeta un proxy si el servidor lo usa

    # ------------------------------------------------------------------ configuración
    def setting(self, key: str, default: str = "") -> str:
        with self.db.conn() as c:
            return get_setting(c, key) or default

    def telegram_token(self) -> str:
        return self.setting("telegram_token")

    def smtp_ready(self) -> bool:
        with self.db.conn() as c:
            return email_ready(c)

    # ------------------------------------------------------------------ envío
    def deliver(self, recipients: set[tuple[str, int]], title: str, body: str, url: str = "/") -> None:
        if not recipients:
            return
        with self.db.conn() as c:
            rows = []
            for role, uid in recipients:
                rows += c.execute("SELECT * FROM alert_channels WHERE role = ? AND user_id = ?", (role, uid)).fetchall()
        for ch in rows:
            self.pool.submit(self._send_safe, dict(ch), title, body, url)

    def _send_safe(self, ch: dict, title: str, body: str, url: str) -> str | None:
        try:
            self.send(ch, title, body, url)
        except Exception as exc:  # noqa: BLE001 - se registra en el canal
            error = str(exc)[:300] or exc.__class__.__name__
            log.warning("Aviso %s %s fallido: %s", ch["kind"], ch["id"], error)
            with self.db.conn() as c:
                if isinstance(exc, PushGone):
                    c.execute("DELETE FROM alert_channels WHERE id = ?", (ch["id"],))
                else:
                    c.execute("UPDATE alert_channels SET last_error = ? WHERE id = ?", (error, ch["id"]))
            return error
        with self.db.conn() as c:
            c.execute("UPDATE alert_channels SET last_ok = ?, last_error = NULL WHERE id = ?", (int(time.time()), ch["id"]))
        return None

    def send(self, ch: dict, title: str, body: str, url: str) -> None:
        if ch["kind"] == "telegram":
            text = f"<b>{_html(title)}</b>\n{_html(body)}"
            self.telegram("sendMessage", {"chat_id": ch["target"], "text": text, "parse_mode": "HTML",
                                          "disable_web_page_preview": True})
        elif ch["kind"] == "email":
            self.email(ch["target"], title, body)
        elif ch["kind"] == "push":
            self.push(json.loads(ch["target"]), {"title": title, "body": body, "url": url, "tag": f"wgp-{int(time.time())}"})

    def telegram(self, method: str, params: dict, token: str | None = None, timeout: int = 15) -> dict:
        token = token or self.telegram_token()
        if not token:
            raise RuntimeError("Telegram no está configurado")
        req = urllib.request.Request(f"https://api.telegram.org/bot{token}/{method}",
                                     data=json.dumps(params).encode(), headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=timeout) as res:
                data = json.loads(res.read())
        except urllib.error.HTTPError as exc:
            try:
                data = json.loads(exc.read())
            except ValueError:
                raise RuntimeError(f"Telegram respondió {exc.code}") from None
        if not data.get("ok"):
            raise RuntimeError(f"Telegram: {data.get('description', 'error')}")
        return data["result"]

    def email(self, to: str, subject: str, body: str) -> None:
        if self.setting("email_provider", "smtp") == "cloudflare":
            return self.email_cloudflare(to, subject, body)
        host = self.setting("smtp_host")
        if not host:
            raise RuntimeError("El email no está configurado")
        port = int(self.setting("smtp_port", "587"))
        security = self.setting("smtp_security", "starttls")
        user, password, sender = self.setting("smtp_user"), self.setting("smtp_password"), self.setting("smtp_from")
        msg = EmailMessage()
        name, addr = parseaddr(sender)
        msg["From"] = formataddr((name or self.brand_name(), addr or sender))
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(f"{body}\n\n— {self.brand_name()}")
        ctx = ssl.create_default_context()
        if security == "ssl":
            server = smtplib.SMTP_SSL(host, port, timeout=20, context=ctx)
        else:
            server = smtplib.SMTP(host, port, timeout=20)
        with server:
            if security == "starttls":
                server.starttls(context=ctx)
            if user:
                server.login(user, password)
            server.send_message(msg)

    def email_cloudflare(self, to: str, subject: str, body: str) -> None:
        """Cloudflare Email Service (API REST): el dominio del remitente debe estar dado de alta en
        Email Service y el token necesita el permiso «Email Sending: Edit»."""
        token = self.setting("cfmail_token") or self.setting("cf_token")
        account, sender = self.setting("cfmail_account"), self.setting("cfmail_from")
        if not (token and account and sender):
            raise RuntimeError("El envío por Cloudflare no está configurado")
        name, addr = parseaddr(sender)
        text = f"{body}\n\n— {self.brand_name()}"
        html_body = "<br>".join(_html(line) for line in text.splitlines())
        payload = {"to": [to], "from": {"address": addr or sender, "name": name or self.brand_name()},
                   "subject": subject, "text": text,
                   "html": f'<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;font-size:15px;line-height:1.5">{html_body}</div>'}
        req = urllib.request.Request(f"{cfdns.API}/accounts/{account}/email/sending/send", method="POST",
                                     data=json.dumps(payload).encode(),
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:   # noqa: S310 - API fija
                data = json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                data = json.loads(exc.read() or b"{}")
            except ValueError:
                data = {}
            msg = "; ".join(f"{e.get('message', '')} ({e.get('code')})" for e in data.get("errors", [])) or f"HTTP {exc.code}"
            raise RuntimeError(f"Cloudflare: {msg}") from None
        if not data.get("success", False):
            raise RuntimeError("Cloudflare: " + ("; ".join(e.get("message", "") for e in data.get("errors", [])) or "envío rechazado"))
        bounced = (data.get("result") or {}).get("permanent_bounces") or []
        if bounced:
            raise RuntimeError(f"Cloudflare: dirección rechazada ({', '.join(map(str, bounced))})")

    def push(self, sub: dict, message: dict) -> None:
        if not push_endpoint_ok(sub["endpoint"]):
            raise PushGone("Servicio de notificaciones no admitido")
        with self.db.conn() as c:
            key, public = vapid_keys(c)
            subject = sender_address(c) or "mailto:admin@wireguard.cloud"
        if not subject.startswith(("mailto:", "https://")):
            subject = f"mailto:{parseaddr(subject)[1] or 'admin@wireguard.cloud'}"
        body = encrypt_push(json.dumps(message).encode(), sub["p256dh"], sub["auth"])
        req = urllib.request.Request(sub["endpoint"], data=body, method="POST", headers={
            "Authorization": vapid_header(sub["endpoint"], key, public, subject),
            "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream",
            "TTL": "86400", "Urgency": "high",
        })
        try:
            with self.opener.open(req, timeout=15) as res:
                res.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410):
                raise PushGone("La suscripción ya no existe") from None
            raise RuntimeError(f"Servicio de push respondió {exc.code}") from None

    # ------------------------------------------------------------------ eventos
    def recipients_for_device(self, c: sqlite3.Connection, tenant_id: int, member_id: int | None) -> set[tuple[str, int]]:
        out: set[tuple[str, int]] = set()
        if prefs(c, "tenant", tenant_id).get("devices"):
            out.add(("tenant", tenant_id))
        if member_id and prefs(c, "member", member_id).get("devices"):
            if c.execute("SELECT 1 FROM members WHERE id = ? AND enabled = 1", (member_id,)).fetchone():
                out.add(("member", member_id))
        for r in c.execute("SELECT id FROM admins"):
            if prefs(c, "admin", r["id"]).get("devices_all"):
                out.add(("admin", r["id"]))
        return out

    def on_monitor_events(self, events: list) -> None:
        for e in events:
            label = "Router" if e.device_kind == "router" else "Dispositivo"
            if e.kind == "device_offline":
                title = f"🔴 {e.device_name} desconectado"
                body = f"{label} de {e.tenant_name}: sin conexión desde las {clock(e.extra.get('since', e.ts))}."
            elif e.kind == "device_online":
                title = f"🟢 {e.device_name} vuelve a estar conectado"
                body = f"{label} de {e.tenant_name}: estuvo desconectado {fmt_duration(e.downtime)}."
            else:
                continue
            with self.db.conn() as c:
                to = self.recipients_for_device(c, e.tenant_id, e.member_id)
            self.deliver(to, title, body, "/#/activity")

    def on_exit_change(self, down: set[int], up: set[int]) -> None:
        with self.db.conn() as c:
            names = {r["id"]: (r["name"], r["failover"]) for r in c.execute("SELECT id, name, failover FROM exits")}
            to = {("admin", r["id"]) for r in c.execute("SELECT id FROM admins") if prefs(c, "admin", r["id"]).get("backup")}
        for i in down:
            name, failover = names.get(i, ("?", 1))
            extra = "Sus dispositivos salen ahora por el servidor principal." if failover else "Sus dispositivos se han quedado sin Internet."
            self.deliver(to, f"🔴 Salida «{name}» sin conexión", extra, "/#/settings")
        for i in up:
            self.deliver(to, f"🟢 Salida «{names.get(i, ('?',))[0]}» conectada de nuevo", "Sus dispositivos vuelven a salir por ella.", "/#/settings")

    def notify_tenant(self, t, title: str, body: str, url: str = "/#/plan") -> None:
        """Avisos de facturación al responsable: sus canales y, si no tiene ese email, su email de facturación."""
        self.deliver({("tenant", t["id"])}, title, body, url)
        email = (t["billing_email"] or "").strip().lower()
        if email and self.smtp_ready():
            with self.db.conn() as c:
                has = c.execute("""SELECT 1 FROM alert_channels WHERE role = 'tenant' AND user_id = ? AND kind = 'email'
                                   AND target = ?""", (t["id"], email)).fetchone()
            if not has:
                self.pool.submit(self._email_safe, email, title, body)

    def _email_safe(self, to: str, title: str, body: str) -> None:
        try:
            self.email(to, title, body)
        except Exception as exc:  # noqa: BLE001
            log.warning("Email de facturación a %s fallido: %s", to, exc)

    def notify_admins(self, title: str, body: str) -> None:
        with self.db.conn() as c:
            to = {("admin", r["id"]) for r in c.execute("SELECT id FROM admins") if prefs(c, "admin", r["id"]).get("billing")}
        self.deliver(to, title, body, "/#/billing")

    def brand_name(self) -> str:
        with self.db.conn() as c:
            return get_setting(c, "brand_name") or self.title

    def notify_system(self, title: str, body: str) -> None:
        """Avisos del servidor (actualizaciones) a los administradores con «backup» activado."""
        with self.db.conn() as c:
            to = {("admin", r["id"]) for r in c.execute("SELECT id FROM admins") if prefs(c, "admin", r["id"]).get("backup")}
        self.deliver(to, title, body, "/#/settings")

    def notify_server(self, title: str, body: str) -> None:
        """Estado del servidor (disco, memoria, CPU) a los administradores con «server» activado."""
        with self.db.conn() as c:
            to = {("admin", r["id"]) for r in c.execute("SELECT id FROM admins") if prefs(c, "admin", r["id"]).get("server")}
        self.deliver(to, title, body, "/#/server")

    def on_backup_failed(self, error: str) -> None:
        with self.db.conn() as c:
            to = {("admin", r["id"]) for r in c.execute("SELECT id FROM admins") if prefs(c, "admin", r["id"]).get("backup")}
        self.deliver(to, "⚠️ Copia de seguridad fallida", error, "/#/settings")

    # ------------------------------------------------------------------ Telegram: vinculación
    def start_telegram(self) -> None:
        """(Re)inicia el long polling si hay token; se llama al arrancar y al cambiar el token."""
        token = self.telegram_token()
        if token == self._tg_token and self._tg_thread and self._tg_thread.is_alive():
            return
        self.stop_telegram()
        self._tg_token = token
        if token:
            self._tg_stop = threading.Event()
            self._tg_thread = threading.Thread(target=self._poll, args=(token, self._tg_stop), daemon=True, name="telegram")
            self._tg_thread.start()

    def stop_telegram(self) -> None:
        self._tg_stop.set()
        self._tg_thread = None

    def _poll(self, token: str, stop: threading.Event) -> None:
        offset = int(self.setting("telegram_offset", "0") or 0)
        while not stop.is_set():
            try:
                updates = self.telegram("getUpdates", {"offset": offset, "timeout": 50, "allowed_updates": ["message"]},
                                        token=token, timeout=65)
            except Exception as exc:  # noqa: BLE001 - red caída, token revocado…
                log.warning("Telegram: %s", exc)
                stop.wait(30)
                continue
            for u in updates:
                offset = max(offset, u["update_id"] + 1)
                try:
                    self.handle_update(u, token)
                except Exception:  # noqa: BLE001
                    log.exception("Error procesando un mensaje de Telegram")
            if updates:
                with self.db.conn() as c:
                    set_setting(c, "telegram_offset", str(offset))

    def handle_update(self, update: dict, token: str | None = None) -> None:
        msg = update.get("message") or {}
        chat = msg.get("chat") or {}
        text = (msg.get("text") or "").strip()
        if chat.get("type") != "private" or not chat.get("id"):
            return
        chat_id = str(chat["id"])
        reply = None
        if text.startswith("/start"):
            code = text[6:].strip()
            with self.db.conn() as c:
                row = c.execute("SELECT * FROM telegram_links WHERE code = ? AND expires_at > ?",
                                (code, int(time.time()))).fetchone() if code else None
                if row is None:
                    reply = "Para recibir avisos, abre el panel › Avisos › «Conectar Telegram»."
                else:
                    c.execute("DELETE FROM telegram_links WHERE code = ?", (code,))
                    label = chat.get("username") and f"@{chat['username']}" or chat.get("first_name") or "Telegram"
                    c.execute("""INSERT INTO alert_channels (role, user_id, kind, target, label, created_at)
                                 VALUES (?, ?, 'telegram', ?, ?, ?)
                                 ON CONFLICT(role, user_id, kind, target) DO UPDATE SET label = excluded.label""",
                              (row["role"], row["user_id"], chat_id, label, int(time.time())))
                    reply = "✅ Avisos activados. Te escribiré aquí si un dispositivo vigilado se desconecta. Envía /stop para dejar de recibirlos."
        elif text.startswith("/stop"):
            with self.db.conn() as c:
                n = c.execute("DELETE FROM alert_channels WHERE kind = 'telegram' AND target = ?", (chat_id,)).rowcount
            reply = "Avisos desactivados." if n else "No tenías avisos activos."
        if reply:
            self.telegram("sendMessage", {"chat_id": chat_id, "text": reply}, token=token)


class PushGone(Exception):
    """La suscripción push ya no es válida: se elimina el canal."""


def _html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def prefs(c: sqlite3.Connection, role: str, user_id: int) -> dict:
    row = c.execute("SELECT prefs FROM alert_prefs WHERE role = ? AND user_id = ?", (role, user_id)).fetchone()
    out = dict(DEFAULT_PREFS[role])
    if row:
        out.update({k: v for k, v in json.loads(row["prefs"]).items() if k in out})
    return out


# --------------------------------------------------------------------------- API
def register(app: FastAPI, d) -> None:
    notifier: Notifier = d.notifier

    def channel_json(r: sqlite3.Row) -> dict:
        return {"id": r["id"], "kind": r["kind"], "label": r["label"],
                "target": r["target"] if r["kind"] == "email" else None,
                "created_at": r["created_at"], "last_ok": r["last_ok"], "last_error": r["last_error"]}

    def state(p, c: sqlite3.Connection) -> dict:
        rows = c.execute("SELECT * FROM alert_channels WHERE role = ? AND user_id = ? ORDER BY created_at, id",
                         (p.role, p.id)).fetchall()
        bot = get_setting(c, "telegram_bot") or ""
        _, public = vapid_keys(c)
        return {
            "channels": [channel_json(r) for r in rows], "prefs": prefs(c, p.role, p.id),
            "available": {"telegram": bool(get_setting(c, "telegram_token")), "telegram_bot": bot,
                          "email": email_ready(c),
                          "push_key": public},
            "delay_min": int(get_setting(c, "alert_delay_min") or 5),
        }

    def channel_for(c: sqlite3.Connection, p, channel_id: int) -> sqlite3.Row:
        row = c.execute("SELECT * FROM alert_channels WHERE id = ? AND role = ? AND user_id = ?",
                        (channel_id, p.role, p.id)).fetchone()
        if not row:
            raise HTTPException(404, "Canal no encontrado")
        return row

    def room(c: sqlite3.Connection, p) -> None:
        n = c.execute("SELECT COUNT(*) FROM alert_channels WHERE role = ? AND user_id = ?", (p.role, p.id)).fetchone()[0]
        if n >= MAX_CHANNELS:
            raise HTTPException(409, f"Máximo {MAX_CHANNELS} canales de aviso")

    @app.get("/api/alerts")
    def get_alerts(p: d.Anyone, c: d.Conn):
        return state(p, c)

    @app.put("/api/alerts/prefs")
    def put_prefs(body: PrefsIn, p: d.Anyone, c: d.Conn):
        cur = prefs(c, p.role, p.id)
        for k, v in body.model_dump(exclude_none=True).items():
            if k in cur:
                cur[k] = v
        c.execute("""INSERT INTO alert_prefs (role, user_id, prefs) VALUES (?, ?, ?)
                     ON CONFLICT(role, user_id) DO UPDATE SET prefs = excluded.prefs""", (p.role, p.id, json.dumps(cur)))
        return state(p, c)

    @app.post("/api/alerts/telegram/link")
    def telegram_link(p: d.Anyone, c: d.Conn):
        bot = get_setting(c, "telegram_bot")
        if not get_setting(c, "telegram_token") or not bot:
            raise HTTPException(409, "Telegram no está configurado en el servidor")
        room(c, p)
        code = secrets.token_urlsafe(18)
        c.execute("DELETE FROM telegram_links WHERE expires_at < ?", (int(time.time()),))
        c.execute("INSERT INTO telegram_links (code, role, user_id, expires_at) VALUES (?, ?, ?, ?)",
                  (code, p.role, p.id, int(time.time()) + LINK_TTL))
        return {"url": f"https://t.me/{bot}?start={code}", "expires_in": LINK_TTL}

    @app.post("/api/alerts/email", status_code=201)
    def add_email(body: EmailIn, p: d.Anyone, c: d.Conn):
        if not email_ready(c):
            raise HTTPException(409, "El envío de emails no está configurado en el servidor")
        email = body.email.strip()
        if not EMAIL_RE.match(email):
            raise HTTPException(422, "Email no válido")
        room(c, p)
        c.execute("""INSERT OR IGNORE INTO alert_channels (role, user_id, kind, target, label, created_at)
                     VALUES (?, ?, 'email', ?, ?, ?)""", (p.role, p.id, email.lower(), email, int(time.time())))
        return state(p, c)

    @app.post("/api/alerts/push", status_code=201)
    def add_push(body: PushIn, p: d.Anyone, c: d.Conn):
        if not push_endpoint_ok(body.endpoint):
            raise HTTPException(422, "Servicio de notificaciones no admitido")
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b64u_decode(body.p256dh))
            if len(b64u_decode(body.auth)) != 16:
                raise ValueError
        except (ValueError, TypeError):
            raise HTTPException(422, "Suscripción no válida") from None
        target = json.dumps({"endpoint": body.endpoint, "p256dh": body.p256dh, "auth": body.auth})
        if not c.execute("SELECT 1 FROM alert_channels WHERE kind = 'push' AND target = ?", (target,)).fetchone():
            room(c, p)
        c.execute("DELETE FROM alert_channels WHERE kind = 'push' AND target = ?", (target,))  # otro usuario en el mismo navegador
        c.execute("""INSERT INTO alert_channels (role, user_id, kind, target, label, created_at)
                     VALUES (?, ?, 'push', ?, ?, ?)""", (p.role, p.id, target, body.label.strip() or "Navegador", int(time.time())))
        return state(p, c)

    @app.delete("/api/alerts/channels/{channel_id}")
    def delete_channel(channel_id: int, p: d.Anyone, c: d.Conn):
        channel_for(c, p, channel_id)
        c.execute("DELETE FROM alert_channels WHERE id = ?", (channel_id,))
        return state(p, c)

    @app.post("/api/alerts/channels/{channel_id}/test")
    def test_channel(channel_id: int, p: d.Anyone, c: d.Conn):
        ch = dict(channel_for(c, p, channel_id))
        c.commit()
        error = notifier._send_safe(ch, "🔔 Aviso de prueba", f"Los avisos de {notifier.brand_name()} llegan correctamente.", "/#/alerts")
        if error:
            raise HTTPException(409, f"No se pudo enviar: {error}")
        return {"ok": True}

    # ---------------------------------------------------------------- configuración (admin)
    def config_state(c: sqlite3.Connection) -> dict:
        return {
            "telegram": {"configured": bool(get_setting(c, "telegram_token")), "bot": get_setting(c, "telegram_bot") or ""},
            "smtp": {"host": get_setting(c, "smtp_host") or "", "port": int(get_setting(c, "smtp_port") or 587),
                     "security": get_setting(c, "smtp_security") or "starttls", "user": get_setting(c, "smtp_user") or "",
                     "password_set": bool(get_setting(c, "smtp_password")), "from": get_setting(c, "smtp_from") or ""},
            "email": {"provider": email_provider(c), "ready": email_ready(c)},
            "cloudflare": {"from": get_setting(c, "cfmail_from") or "", "account": get_setting(c, "cfmail_account") or "",
                           "own_token": bool(get_setting(c, "cfmail_token")), "dns_token": bool(get_setting(c, "cf_token"))},
            "delay_min": int(get_setting(c, "alert_delay_min") or 5),
        }

    @app.get("/api/admin/alerts-config")
    def get_config(_: d.Admin, c: d.Conn):
        return config_state(c)

    @app.post("/api/admin/alerts-config/test-email")
    def test_email(body: EmailIn, _: d.Admin, c: d.Conn):
        if not email_ready(c):
            raise HTTPException(409, "El envío de emails no está configurado")
        try:
            notifier.email(body.email.strip(), "🔔 Prueba de email",
                           f"Si lees esto, {notifier.brand_name()} ya puede enviar avisos por email.")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(409, f"No se pudo enviar: {exc}") from None
        return {"ok": True}

    @app.put("/api/admin/alerts-config")
    def put_config(body: AlertsConfigIn, _: d.Admin, c: d.Conn):
        if body.telegram_token is not None:
            token = body.telegram_token.strip()
            if token:
                if not TOKEN_RE.match(token):
                    raise HTTPException(422, "Token no válido (formato 123456789:AA…, de @BotFather)")
                try:
                    me = notifier.telegram("getMe", {}, token=token)
                except Exception as exc:  # noqa: BLE001
                    raise HTTPException(409, f"Telegram rechazó el token: {exc}") from None
                set_setting(c, "telegram_bot", me.get("username", ""))
                set_setting(c, "telegram_offset", "0")
            else:
                set_setting(c, "telegram_bot", "")
            set_setting(c, "telegram_token", token)
        for key in ("smtp_host", "smtp_user", "smtp_from"):
            value = getattr(body, key)
            if value is not None:
                if "\n" in value or "\r" in value:
                    raise HTTPException(422, "Valor no válido")
                set_setting(c, key, value.strip())
        if body.smtp_from and not EMAIL_RE.match(parseaddr(body.smtp_from)[1]):
            raise HTTPException(422, "Remitente no válido (p. ej. avisos@tudominio.com)")
        if body.smtp_port is not None:
            set_setting(c, "smtp_port", str(body.smtp_port))
        if body.smtp_security is not None:
            set_setting(c, "smtp_security", body.smtp_security)
        if body.smtp_password:
            set_setting(c, "smtp_password", body.smtp_password)
        if body.cf_from is not None or body.cf_token is not None or body.cf_account is not None:
            sender = (body.cf_from if body.cf_from is not None else get_setting(c, "cfmail_from") or "").strip()
            if "\n" in sender or "\r" in sender or not EMAIL_RE.match(parseaddr(sender)[1]):
                raise HTTPException(422, "Remitente no válido (p. ej. Avisos <avisos@tudominio.com>)")
            if body.cf_token is not None:
                set_setting(c, "cfmail_token", body.cf_token.strip())
            token = get_setting(c, "cfmail_token") or get_setting(c, "cf_token")
            if not token:
                raise HTTPException(422, "Pega un token de Cloudflare con el permiso «Email Sending: Edit»")
            account = (body.cf_account or "").strip().lower()
            if not account and not body.cf_token:
                account = get_setting(c, "cf_account") or ""   # la de Subdominios de clientes
            if not account:   # la cuenta del dominio del remitente
                domain = parseaddr(sender)[1].rsplit("@", 1)[1].lower()
                try:
                    zones = cfdns.CloudflareDNS(d.db, d.doms).call(token, "GET", "/zones", query={"per_page": 50}).get("result", [])
                except cfdns.CloudflareError as exc:
                    raise HTTPException(400, f"Cloudflare: {exc}") from None
                zone = next((z for z in zones if domain == z["name"] or domain.endswith("." + z["name"])), None)
                if not zone:
                    raise HTTPException(422, f"El token no ve el dominio {domain}: indica el ID de cuenta de Cloudflare")
                account = zone["account"]["id"]
            if not re.fullmatch(r"[0-9a-f]{32}", account):
                raise HTTPException(422, "ID de cuenta no válido (32 caracteres hexadecimales)")
            set_setting(c, "cfmail_from", sender)
            set_setting(c, "cfmail_account", account)
        if body.email_provider is not None:
            set_setting(c, "email_provider", body.email_provider)
        if body.delay_min is not None:
            set_setting(c, "alert_delay_min", str(body.delay_min))
        c.commit()
        notifier.start_telegram()
        return config_state(c)

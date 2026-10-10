"""Seguridad de la cuenta: email verificado, recuperación de contraseña y verificación en dos pasos.

Cada persona (administrador, cliente o usuario de un cliente) puede guardar un
email en su Cuenta. Se verifica con un código de 6 cifras y sirve para:

  * recuperar la contraseña: «¿Has olvidado tu contraseña?» envía un enlace de un
    solo uso (1 h). La respuesta es siempre la misma, exista o no la cuenta;
  * la verificación en dos pasos: tras la contraseña se pide un código de 6 cifras
    enviado a ese email (10 min, 5 intentos). Entrar con llave biométrica no lo
    pide: la llave ya es un segundo factor.

Los emails salen por lo configurado en Ajustes › Avisos (SMTP o Cloudflare). En
la base de datos sólo se guarda el hash de cada código o enlace.

Sin `from __future__ import annotations`: FastAPI evalúa las dependencias de `deps`.
"""
import hashlib
import hmac
import logging
import re
import secrets
import sqlite3
import time
from typing import Optional

from fastapi import HTTPException, Request, Response
from pydantic import BaseModel, Field

from . import alerts, domains, security

log = logging.getLogger("wgp.account")

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
ROLE_TABLE = {"admin": "admins", "tenant": "tenants", "member": "members"}
CODE_TTL = 10 * 60
RESET_TTL = 60 * 60
MAX_ATTEMPTS = 5
RESEND_EVERY = 45


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def mask(email: str) -> str:
    user, _, host = email.partition("@")
    name, _, tld = host.rpartition(".")
    return f"{user[:1]}{'•' * max(2, len(user) - 1)}@{name[:1]}{'•' * max(2, len(name) - 1)}.{tld}"


def get(c: sqlite3.Connection, role: str, uid: int) -> Optional[sqlite3.Row]:
    return c.execute("SELECT * FROM account_security WHERE role = ? AND user_id = ?", (role, uid)).fetchone()


def needs_2fa(c: sqlite3.Connection, role: str, uid: int) -> bool:
    r = get(c, role, uid)
    return bool(r and r["twofa"] and r["email"] and r["verified_at"])


class EmailIn(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class CodeIn(BaseModel):
    code: str = Field(min_length=4, max_length=12)


class PasswordOnly(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class TwoFaIn(BaseModel):
    enabled: bool
    password: str = Field(min_length=1, max_length=256)


class ChallengeIn(BaseModel):
    challenge: str = Field(min_length=10, max_length=100)
    code: Optional[str] = Field(default=None, max_length=12)


class ForgotIn(BaseModel):
    login: str = Field(min_length=1, max_length=254)


class ResetIn(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    password: str = Field(min_length=8, max_length=256)


def register(app, d) -> None:
    notifier = d.notifier
    limiter = d.limiter

    def send(c: sqlite3.Connection, to: str, subject: str, body: str) -> None:
        if not alerts.email_ready(c):
            raise HTTPException(409, "El servidor no tiene configurado el envío de emails (Ajustes › Avisos)")
        try:
            notifier.email(to, subject, body)
        except Exception as exc:  # noqa: BLE001
            log.warning("No se pudo enviar el email a %s: %s", to, exc)
            raise HTTPException(502, "No se pudo enviar el email. Inténtalo más tarde.") from None

    def check_password(c: sqlite3.Connection, p, password: str) -> None:
        row = c.execute(f"SELECT password_hash FROM {ROLE_TABLE[p.role]} WHERE id = ?", (p.id,)).fetchone()
        if not row or not security.verify_password(password, row["password_hash"]):
            raise HTTPException(400, "La contraseña no es correcta")

    def state(c: sqlite3.Connection, p) -> dict:
        r = get(c, p.role, p.id)
        pending = c.execute("""SELECT email FROM auth_codes WHERE kind = 'verify' AND role = ? AND user_id = ?
                               AND used = 0 AND expires_at > ? ORDER BY id DESC LIMIT 1""",
                            (p.role, p.id, int(time.time()))).fetchone()
        return {"email": r["email"] if r else None, "verified": bool(r and r["verified_at"]),
                "twofa": bool(r and r["twofa"]), "pending": pending["email"] if pending else None,
                "email_available": alerts.email_ready(c)}

    def issue(c: sqlite3.Connection, kind: str, role: str, uid: int, email: str, secret: str, ttl: int,
              challenge: Optional[str] = None) -> None:
        now = int(time.time())
        c.execute("UPDATE auth_codes SET used = 1 WHERE kind = ? AND role = ? AND user_id = ? AND used = 0", (kind, role, uid))
        c.execute("""INSERT INTO auth_codes (kind, role, user_id, email, secret_hash, challenge_hash, created_at, expires_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                  (kind, role, uid, email, digest(secret), digest(challenge) if challenge else None, now, now + ttl))
        c.execute("DELETE FROM auth_codes WHERE expires_at < ?", (now - 86400,))

    def recent(c: sqlite3.Connection, kind: str, role: str, uid: int) -> bool:
        row = c.execute("SELECT created_at FROM auth_codes WHERE kind = ? AND role = ? AND user_id = ? ORDER BY id DESC LIMIT 1",
                        (kind, role, uid)).fetchone()
        return bool(row and time.time() - row["created_at"] < RESEND_EVERY)

    def link_base(c: sqlite3.Connection, request: Request) -> str:
        """Base del enlace de recuperación: el dominio desde el que se pide, si es uno de los nuestros
        (panel, cliente o página pública); si no (IP o un Host inventado), el del panel."""
        host = domains.host_of(request.headers.get("host"))
        known = {d.doms.main_domain(c), *d.doms.site_domains(c, only_enabled=True)}
        if host and (host in known or d.doms.tenant_for_host(c, host) is not None):
            return f"https://{host}"
        main = d.doms.main_domain(c)
        if main:
            return f"https://{main}"
        # Sin dominio: la IP pública del servidor (nunca el Host de la petición, que lo elige quien la envía).
        ips = sorted(d.doms.expected_ips())
        ip = host if host in ips else (ips[0] if ips else None)
        if not ip:
            raise HTTPException(409, "Configura el dominio del panel para poder enviar enlaces de recuperación")
        port = request.url.port
        return f"{request.url.scheme}://{ip}" + (f":{port}" if port and port not in (80, 443) else "")

    # ---------------------------------------------------------------- email de la cuenta
    @app.get("/api/me/security")
    def get_security(p: d.Anyone, c: d.Conn):
        return state(c, p)

    @app.post("/api/me/email")
    def set_email(body: EmailIn, p: d.Anyone, c: d.Conn):
        check_password(c, p, body.password)
        email = body.email.strip().lower()
        if not EMAIL_RE.match(email):
            raise HTTPException(422, "Email no válido")
        if recent(c, "verify", p.role, p.id):
            raise HTTPException(429, "Espera un momento antes de pedir otro código")
        code = new_code()
        issue(c, "verify", p.role, p.id, email, code, CODE_TTL)
        c.commit()
        send(c, email, f"{code} es tu código de verificación",
             f"Hola {p.name}:\n\nPara confirmar este email en tu cuenta «{p.username}», escribe este código:\n\n    {code}\n\n"
             "Caduca en 10 minutos. Si no lo has pedido tú, ignora este mensaje.")
        return state(c, p)

    @app.post("/api/me/email/verify")
    def verify_email(body: CodeIn, p: d.Anyone, c: d.Conn):
        now = int(time.time())
        row = c.execute("""SELECT * FROM auth_codes WHERE kind = 'verify' AND role = ? AND user_id = ? AND used = 0
                           AND expires_at > ? ORDER BY id DESC LIMIT 1""", (p.role, p.id, now)).fetchone()
        if not row:
            raise HTTPException(400, "El código ha caducado: pide otro")
        if row["attempts"] >= MAX_ATTEMPTS:
            raise HTTPException(429, "Demasiados intentos: pide otro código")
        if not hmac.compare_digest(row["secret_hash"], digest(body.code.strip())):
            c.execute("UPDATE auth_codes SET attempts = attempts + 1 WHERE id = ?", (row["id"],))
            c.commit()
            raise HTTPException(400, "Código incorrecto")
        c.execute("UPDATE auth_codes SET used = 1 WHERE id = ?", (row["id"],))
        c.execute("""INSERT INTO account_security (role, user_id, email, verified_at, twofa) VALUES (?, ?, ?, ?, 0)
                     ON CONFLICT(role, user_id) DO UPDATE SET email = excluded.email, verified_at = excluded.verified_at""",
                  (p.role, p.id, row["email"], now))
        return state(c, p)

    @app.delete("/api/me/email")
    def delete_email(body: PasswordOnly, p: d.Anyone, c: d.Conn):
        check_password(c, p, body.password)
        c.execute("DELETE FROM account_security WHERE role = ? AND user_id = ?", (p.role, p.id))
        return state(c, p)

    @app.put("/api/me/2fa")
    def set_twofa(body: TwoFaIn, p: d.Anyone, c: d.Conn):
        check_password(c, p, body.password)
        r = get(c, p.role, p.id)
        if body.enabled and not (r and r["verified_at"]):
            raise HTTPException(409, "Primero añade y verifica tu email")
        if body.enabled and not alerts.email_ready(c):
            raise HTTPException(409, "El servidor no tiene configurado el envío de emails")
        if r:
            c.execute("UPDATE account_security SET twofa = ? WHERE role = ? AND user_id = ?", (int(body.enabled), p.role, p.id))
        return state(c, p)

    # ---------------------------------------------------------------- inicio de sesión en dos pasos
    def start_challenge(c: sqlite3.Connection, role: str, row: sqlite3.Row) -> dict:
        """La contraseña es correcta y la cuenta tiene la verificación en dos pasos: código por email."""
        r = get(c, role, row["id"])
        challenge = secrets.token_urlsafe(24)
        code = new_code()
        issue(c, "login", role, row["id"], r["email"], code, CODE_TTL, challenge)
        c.commit()
        send(c, r["email"], f"{code} es tu código para entrar",
             f"Código para entrar en tu cuenta «{row['username']}»:\n\n    {code}\n\nCaduca en 10 minutos. "
             "Si no has sido tú, alguien conoce tu contraseña: cámbiala cuanto antes.")
        return {"twofa": True, "challenge": challenge, "email": mask(r["email"])}

    d.start_2fa = start_challenge

    def pending(c: sqlite3.Connection, challenge: str) -> sqlite3.Row:
        row = c.execute("""SELECT * FROM auth_codes WHERE kind = 'login' AND challenge_hash = ? AND used = 0 AND expires_at > ?""",
                        (digest(challenge), int(time.time()))).fetchone()
        if not row:
            raise HTTPException(410, "El código ha caducado: vuelve a introducir tu contraseña")
        return row

    @app.post("/api/auth/2fa")
    def login_2fa(body: ChallengeIn, request: Request, response: Response, c: d.Conn):
        key = request.client.host if request.client else "unknown"
        if limiter.blocked(key):
            raise HTTPException(429, "Demasiados intentos. Espere unos minutos.")
        row = pending(c, body.challenge)
        if row["attempts"] >= MAX_ATTEMPTS:
            c.execute("UPDATE auth_codes SET used = 1 WHERE id = ?", (row["id"],))
            c.commit()
            raise HTTPException(410, "Demasiados intentos: vuelve a introducir tu contraseña")
        if not hmac.compare_digest(row["secret_hash"], digest((body.code or "").strip())):
            c.execute("UPDATE auth_codes SET attempts = attempts + 1 WHERE id = ?", (row["id"],))
            c.commit()
            limiter.hit(key)
            raise HTTPException(400, "Código incorrecto")
        c.execute("UPDATE auth_codes SET used = 1 WHERE id = ?", (row["id"],))
        user = c.execute(f"SELECT * FROM {ROLE_TABLE[row['role']]} WHERE id = ?", (row["user_id"],)).fetchone()
        if user is None:
            raise HTTPException(401, "La cuenta ya no existe")
        limiter.reset(key)
        return d.finish_login(request, response, c, row["role"], user)

    @app.post("/api/auth/2fa/resend")
    def resend_2fa(body: ChallengeIn, c: d.Conn):
        row = pending(c, body.challenge)
        if time.time() - row["created_at"] < RESEND_EVERY:
            raise HTTPException(429, "Espera unos segundos antes de pedir otro código")
        user = c.execute(f"SELECT * FROM {ROLE_TABLE[row['role']]} WHERE id = ?", (row["user_id"],)).fetchone()
        code = new_code()
        issue(c, "login", row["role"], row["user_id"], row["email"], code, CODE_TTL, body.challenge)
        c.commit()
        send(c, row["email"], f"{code} es tu código para entrar",
             f"Código para entrar en tu cuenta «{user['username']}»:\n\n    {code}\n\nCaduca en 10 minutos.")
        return {"ok": True}

    # ---------------------------------------------------------------- recuperar la contraseña
    @app.get("/api/auth/forgot")
    def forgot_available(c: d.Conn):
        return {"enabled": alerts.email_ready(c)}

    @app.post("/api/auth/forgot")
    def forgot(body: ForgotIn, request: Request, c: d.Conn):
        key = "forgot:" + (request.client.host if request.client else "unknown")
        if limiter.blocked(key):
            raise HTTPException(429, "Demasiados intentos. Espere unos minutos.")
        limiter.hit(key)
        if not alerts.email_ready(c):
            raise HTTPException(409, "La recuperación por email no está disponible: pide ayuda a tu proveedor")
        login = body.login.strip()
        targets = []   # (rol, fila, email)
        if "@" in login:
            for r in c.execute("SELECT * FROM account_security WHERE email = ? AND verified_at IS NOT NULL LIMIT 5", (login.lower(),)):
                user = c.execute(f"SELECT * FROM {ROLE_TABLE[r['role']]} WHERE id = ?", (r["user_id"],)).fetchone()
                if user:
                    targets.append((r["role"], user, r["email"]))
        else:
            for role, table in ROLE_TABLE.items():
                user = c.execute(f"SELECT * FROM {table} WHERE username = ? COLLATE NOCASE", (login,)).fetchone()
                r = get(c, role, user["id"]) if user else None
                if r and r["verified_at"]:
                    targets.append((role, user, r["email"]))
                    break
        base = link_base(c, request)
        for role, user, email in targets:
            if recent(c, "reset", role, user["id"]):
                continue
            token = secrets.token_urlsafe(32)
            issue(c, "reset", role, user["id"], email, token, RESET_TTL)
            c.commit()
            try:
                notifier.email(email, "Recupera tu contraseña",
                               f"Hola:\n\nHas pedido cambiar la contraseña de tu cuenta «{user['username']}». Ábrelo aquí "
                               f"(caduca en 1 hora y sirve una sola vez):\n\n{base}/#/reset?token={token}\n\n"
                               "Si no lo has pedido tú, ignora este mensaje: tu contraseña no cambia.")
            except Exception as exc:  # noqa: BLE001 - la respuesta no revela si la cuenta existe
                log.warning("No se pudo enviar el enlace de recuperación: %s", exc)
        return {"ok": True}

    @app.post("/api/auth/reset")
    def reset(body: ResetIn, request: Request, c: d.Conn):
        key = "reset:" + (request.client.host if request.client else "unknown")
        if limiter.blocked(key):
            raise HTTPException(429, "Demasiados intentos. Espere unos minutos.")
        row = c.execute("SELECT * FROM auth_codes WHERE kind = 'reset' AND secret_hash = ? AND used = 0 AND expires_at > ?",
                        (digest(body.token), int(time.time()))).fetchone()
        if not row:
            limiter.hit(key)
            raise HTTPException(400, "El enlace no es válido o ha caducado: pide otro")
        table = ROLE_TABLE[row["role"]]
        # Cambia la versión de la contraseña: se cierran todas las sesiones abiertas.
        c.execute(f"UPDATE {table} SET password_hash = ?, must_change = 0 WHERE id = ?",
                  (security.hash_password(body.password), row["user_id"]))
        c.execute("UPDATE auth_codes SET used = 1 WHERE role = ? AND user_id = ? AND used = 0", (row["role"], row["user_id"]))
        user = c.execute(f"SELECT username FROM {table} WHERE id = ?", (row["user_id"],)).fetchone()
        return {"ok": True, "username": user["username"] if user else None}

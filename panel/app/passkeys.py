"""Inicio de sesión biométrico con passkeys (WebAuthn / FIDO2).

Face ID, Touch ID, la huella de Android o Windows Hello generan en el propio
dispositivo un par de claves ligado al dominio del panel. El servidor sólo
guarda la clave pública: en cada inicio de sesión el dispositivo firma un reto
aleatorio tras verificar la biometría del usuario (user verification).

La verificación criptográfica la hace la librería `webauthn` (Duo Security).
Los retos son de un solo uso, caducan en 5 minutos y se guardan en memoria.
"""
from __future__ import annotations

import ipaddress
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass

from fastapi import Request
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

CHALLENGE_TTL = 300
MAX_PASSKEYS = 10


class PasskeyError(Exception):
    pass


@dataclass
class RelyingParty:
    rp_id: str
    origin: str


def relying_party(request: Request) -> RelyingParty:
    """RP ID = dominio con el que se abre el panel. WebAuthn exige HTTPS (o localhost) y no admite IPs."""
    host_header = request.headers.get("host", "")
    host = host_header.rsplit(":", 1)[0] if host_header.count(":") == 1 else host_header
    host = host.lower()
    secure = request.url.scheme == "https" or host == "localhost"
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False
    if not host or is_ip or not secure:
        raise PasskeyError("La llave biométrica requiere abrir el panel con un dominio y HTTPS (Ajustes → Dominio).")
    return RelyingParty(rp_id=host, origin=f"{request.url.scheme}://{host_header.lower()}")


class Passkeys:
    def __init__(self) -> None:
        self._pending: dict[str, tuple[float, bytes, dict]] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ retos
    def _issue(self, challenge: bytes, ctx: dict) -> str:
        state = secrets.token_urlsafe(24)
        now = time.monotonic()
        with self._lock:
            for k in [k for k, v in self._pending.items() if v[0] < now]:
                del self._pending[k]
            self._pending[state] = (now + CHALLENGE_TTL, challenge, ctx)
        return state

    def _take(self, state: str) -> tuple[bytes, dict]:
        with self._lock:
            item = self._pending.pop(state, None)
        if not item or item[0] < time.monotonic():
            raise PasskeyError("La solicitud ha caducado. Inténtalo de nuevo.")
        return item[1], item[2]

    # ------------------------------------------------------------------ alta
    def registration_options(self, c: sqlite3.Connection, rp: RelyingParty, rp_name: str,
                             role: str, uid: int, username: str, display: str) -> tuple[str, str]:
        existing = c.execute("SELECT credential_id FROM passkeys WHERE role = ? AND user_id = ? AND rp_id = ?",
                             (role, uid, rp.rp_id)).fetchall()
        total = c.execute("SELECT COUNT(*) FROM passkeys WHERE role = ? AND user_id = ?", (role, uid)).fetchone()[0]
        if total >= MAX_PASSKEYS:
            raise PasskeyError(f"Máximo {MAX_PASSKEYS} llaves por usuario. Elimina alguna antes de añadir otra.")
        options = generate_registration_options(
            rp_id=rp.rp_id,
            rp_name=rp_name,
            user_id=f"{role}:{uid}".encode(),
            user_name=username,
            user_display_name=display,
            exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"])) for r in existing],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,          # passkey «descubrible»: sin escribir usuario
                user_verification=UserVerificationRequirement.REQUIRED,  # biometría o PIN del dispositivo
            ),
            timeout=CHALLENGE_TTL * 1000,
        )
        state = self._issue(options.challenge, {"kind": "reg", "role": role, "uid": uid, "rp": rp.rp_id, "origin": rp.origin})
        return state, options_to_json(options)

    def register(self, c: sqlite3.Connection, rp: RelyingParty, state: str, credential: dict,
                 role: str, uid: int, name: str) -> None:
        challenge, ctx = self._take(state)
        if ctx.get("kind") != "reg" or ctx["role"] != role or ctx["uid"] != uid or ctx["rp"] != rp.rp_id:
            raise PasskeyError("Solicitud no válida")
        try:
            v = verify_registration_response(
                credential=credential, expected_challenge=challenge,
                expected_rp_id=rp.rp_id, expected_origin=rp.origin, require_user_verification=True,
            )
        except Exception as exc:  # noqa: BLE001 - la librería lanza varios tipos
            raise PasskeyError(f"No se pudo verificar la llave: {exc}") from exc
        transports = ",".join((credential.get("response") or {}).get("transports") or [])
        c.execute(
            """INSERT INTO passkeys (role, user_id, credential_id, public_key, sign_count, rp_id, name, transports, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (role, uid, bytes_to_base64url(v.credential_id), v.credential_public_key, v.sign_count,
             rp.rp_id, name[:60] or "Llave biométrica", transports, int(time.time())),
        )

    # ------------------------------------------------------------------ inicio de sesión
    def authentication_options(self, rp: RelyingParty) -> tuple[str, str]:
        options = generate_authentication_options(
            rp_id=rp.rp_id,
            user_verification=UserVerificationRequirement.REQUIRED,
            allow_credentials=[],  # el dispositivo ofrece sus passkeys para este dominio
            timeout=CHALLENGE_TTL * 1000,
        )
        return self._issue(options.challenge, {"kind": "auth", "rp": rp.rp_id, "origin": rp.origin}), options_to_json(options)

    def authenticate(self, c: sqlite3.Connection, rp: RelyingParty, state: str, credential: dict) -> sqlite3.Row:
        challenge, ctx = self._take(state)
        if ctx.get("kind") != "auth" or ctx["rp"] != rp.rp_id:
            raise PasskeyError("Solicitud no válida")
        row = c.execute("SELECT * FROM passkeys WHERE credential_id = ? AND rp_id = ?",
                        (str(credential.get("id", "")), rp.rp_id)).fetchone()
        if row is None:
            raise PasskeyError("Esta llave no está registrada en este panel. Entra con tu contraseña y vuelve a activarla.")
        handle = (credential.get("response") or {}).get("userHandle")
        if handle and base64url_to_bytes(handle) != f"{row['role']}:{row['user_id']}".encode():
            raise PasskeyError("La llave no corresponde a este usuario")
        try:
            v = verify_authentication_response(
                credential=credential, expected_challenge=challenge,
                expected_rp_id=rp.rp_id, expected_origin=rp.origin,
                credential_public_key=row["public_key"], credential_current_sign_count=row["sign_count"],
                require_user_verification=True,
            )
        except Exception as exc:  # noqa: BLE001
            raise PasskeyError(f"No se pudo verificar la llave: {exc}") from exc
        c.execute("UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?",
                  (v.new_sign_count, int(time.time()), row["id"]))
        return row

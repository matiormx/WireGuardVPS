"""Passkeys con un autenticador software que genera respuestas WebAuthn reales (ES256)."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from app.main import create_app

H = {"X-WGP": "1"}
ORIGIN = "https://panel.example.com"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SoftAuthenticator:
    """Emula Face ID / huella: credencial residente con verificación de usuario."""

    def __init__(self, origin: str = ORIGIN):
        self.origin = origin
        self.creds: dict[str, dict] = {}

    def create(self, options: dict) -> dict:
        key = ec.generate_private_key(ec.SECP256R1())
        cred_id = os.urandom(16)
        nums = key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        rp_hash = hashlib.sha256(options["rp"]["id"].encode()).digest()
        auth_data = rp_hash + bytes([0x45]) + struct.pack(">I", 0) + bytes(16) + struct.pack(">H", 16) + cred_id + cose
        client = json.dumps({"type": "webauthn.create", "challenge": options["challenge"], "origin": self.origin}).encode()
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        self.creds[b64u(cred_id)] = {"key": key, "rp": options["rp"]["id"], "user": options["user"]["id"], "count": 0}
        return {"id": b64u(cred_id), "rawId": b64u(cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(client), "attestationObject": b64u(att), "transports": ["internal"]},
                "clientExtensionResults": {}, "authenticatorAttachment": "platform"}

    def get(self, options: dict, cred_id: str | None = None, tamper: bool = False) -> dict:
        cred_id = cred_id or next(k for k, v in self.creds.items() if v["rp"] == options["rpId"])
        c = self.creds[cred_id]
        c["count"] += 1
        rp_hash = hashlib.sha256(options["rpId"].encode()).digest()
        auth_data = rp_hash + bytes([0x05]) + struct.pack(">I", c["count"])
        client = json.dumps({"type": "webauthn.get", "challenge": options["challenge"], "origin": self.origin}).encode()
        sig = c["key"].sign(auth_data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        if tamper:
            sig = sig[:-2] + bytes([sig[-2] ^ 1, sig[-1]])
        return {"id": cred_id, "rawId": cred_id, "type": "public-key",
                "response": {"clientDataJSON": b64u(client), "authenticatorData": b64u(auth_data),
                             "signature": b64u(sig), "userHandle": c["user"]},
                "clientExtensionResults": {}, "authenticatorAttachment": "platform"}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("WG_CONF_DIR", str(tmp_path / "wireguard"))
    monkeypatch.setenv("WG_ENDPOINT", "203.0.113.10")
    monkeypatch.setenv("SESSION_SECRET", "x")
    monkeypatch.setenv("DNS_ENABLED", "false")


def client(app, base=ORIGIN):
    return TestClient(app, base_url=base)


def ready_admin(c):
    c.post("/api/auth/login", json={"username": "admin", "password": "admin"}, headers=H)
    c.post("/api/me/password", json={"current": "admin", "new": "AdminPass1"}, headers=H)


def register(c, auth, name="iPhone"):
    o = c.post("/api/passkeys/register/options", headers=H).json()
    return c.post("/api/passkeys/register/verify", json={"state": o["state"], "credential": auth.create(o["options"]), "name": name}, headers=H)


def passkey_login(c, auth, **kw):
    o = c.post("/api/passkeys/login/options", headers=H).json()
    return c.post("/api/passkeys/login/verify", json={"state": o["state"], "credential": auth.get(o["options"], **kw)}, headers=H), o


def test_register_and_login_with_passkey(env):
    app = create_app()
    auth = SoftAuthenticator()
    with client(app) as c:
        ready_admin(c)
        assert c.get("/api/passkeys").json() == {"available": True, "rp_id": "panel.example.com", "passkeys": []}
        o = c.post("/api/passkeys/register/options", headers=H).json()["options"]
        assert o["rp"]["id"] == "panel.example.com"
        assert o["authenticatorSelection"]["residentKey"] == "required"
        assert o["authenticatorSelection"]["userVerification"] == "required"
        r = register(c, auth)
        assert r.status_code == 201, r.text
        keys = r.json()["passkeys"]
        assert len(keys) == 1 and keys[0]["name"] == "iPhone" and keys[0]["current"]

    with client(app) as c2:  # otra sesión, sin contraseña
        assert c2.get("/api/me").status_code == 401
        r, _ = passkey_login(c2, auth)
        assert r.status_code == 200 and r.json()["role"] == "admin"
        assert "Secure" in r.headers["set-cookie"]
        assert c2.get("/api/me").json()["username"] == "admin"
        assert c2.get("/api/passkeys").json()["passkeys"][0]["last_used_at"]


def test_rejections(env):
    app = create_app()
    auth = SoftAuthenticator()
    with client(app) as c:
        ready_admin(c)
        register(c, auth)
    with client(app) as c2:
        # firma manipulada
        r, _ = passkey_login(c2, auth, tamper=True)
        assert r.status_code == 401
        # reto reutilizado (un solo uso)
        o = c2.post("/api/passkeys/login/options", headers=H).json()
        cred = auth.get(o["options"])
        assert c2.post("/api/passkeys/login/verify", json={"state": o["state"], "credential": cred}, headers=H).status_code == 200
        assert c2.post("/api/passkeys/login/verify", json={"state": o["state"], "credential": cred}, headers=H).status_code == 401
        # llave desconocida
        other = SoftAuthenticator()
        other.create({"rp": {"id": "panel.example.com"}, "user": {"id": b64u(b"admin:1")}, "challenge": "x"})
        r, _ = passkey_login(c2, other)
        assert r.status_code == 401 and "no está registrada" in r.json()["detail"]

    # Otro dominio: la llave está ligada al dominio en el que se creó
    with client(app, "https://otro.example.com") as c3:
        o = c3.post("/api/passkeys/login/options", headers=H).json()["options"]
        assert o["rpId"] == "otro.example.com"

    # Sin HTTPS ni dominio no está disponible
    with client(app, "http://203.0.113.10:5000") as c4:
        r = c4.post("/api/passkeys/login/options", headers=H)
        assert r.status_code == 400 and "HTTPS" in r.json()["detail"]
    with client(app, "http://localhost:5000") as c5:  # localhost sí (desarrollo)
        assert c5.post("/api/passkeys/login/options", headers=H).status_code == 200


def test_tenant_passkey_rules(env):
    app = create_app()
    auth = SoftAuthenticator()
    with client(app) as adm:
        ready_admin(adm)
        t = adm.post("/api/admin/tenants", json={"name": "Acme", "username": "acme", "password": "Password1"}, headers=H).json()
        with client(app) as c:
            c.post("/api/auth/login", json={"username": "acme", "password": "Password1"}, headers=H)
            # pendiente de cambiar contraseña: aún no puede registrar llaves
            assert c.post("/api/passkeys/register/options", headers=H).status_code == 403
            c.post("/api/me/password", json={"current": "Password1", "new": "AcmePass22"}, headers=H)
            assert register(c, auth).status_code == 201
            kid = c.get("/api/passkeys").json()["passkeys"][0]["id"]
            # el admin no ve ni borra las llaves del cliente
            assert adm.get("/api/passkeys").json()["passkeys"] == []
            assert adm.delete(f"/api/passkeys/{kid}", headers=H).status_code == 404

        # cliente suspendido: la llave no le deja entrar
        adm.patch(f"/api/admin/tenants/{t['id']}", json={"enabled": False}, headers=H)
        with client(app) as c2:
            r, _ = passkey_login(c2, auth)
            assert r.status_code == 403
        adm.patch(f"/api/admin/tenants/{t['id']}", json={"enabled": True}, headers=H)
        with client(app) as c3:
            r, _ = passkey_login(c3, auth)
            assert r.status_code == 200 and r.json()["role"] == "tenant"
            assert c3.delete(f"/api/passkeys/{kid}", headers=H).json()["passkeys"] == []
        # cliente eliminado: sus llaves desaparecen
        with client(app) as c4:
            c4.post("/api/auth/login", json={"username": "acme", "password": "AcmePass22"}, headers=H)
            assert register(c4, auth, "Mac").status_code == 201
        adm.delete(f"/api/admin/tenants/{t['id']}", headers=H)
        with client(app) as c5:
            r, _ = passkey_login(c5, auth, cred_id=list(auth.creds)[-1])
            assert r.status_code == 401

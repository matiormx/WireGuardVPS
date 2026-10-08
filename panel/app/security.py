"""Hash de contraseñas, sesiones firmadas y limitador de intentos de login."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import threading
import time
from collections import defaultdict, deque

from itsdangerous import BadSignature, URLSafeTimedSerializer

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N, _SCRYPT_R, _SCRYPT_P,
        base64.b64encode(salt).decode(), base64.b64encode(digest).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest_b64)
        digest = hashlib.scrypt(
            password.encode(), salt=base64.b64decode(salt_b64),
            n=int(n), r=int(r), p=int(p), dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, expected)


def password_version(stored_hash: str) -> str:
    """Huella corta del hash: cambia al cambiar la contraseña e invalida sesiones."""
    return hashlib.sha256(stored_hash.encode()).hexdigest()[:16]


class SessionManager:
    COOKIE = "wgp_session"

    def __init__(self, secret: str, max_age: int) -> None:
        self._serializer = URLSafeTimedSerializer(secret, salt="wgp-session")
        self.max_age = max_age

    def dump(self, role: str, uid: int, pwv: str) -> str:
        return self._serializer.dumps({"role": role, "uid": uid, "pwv": pwv})

    def load(self, token: str | None) -> dict | None:
        if not token:
            return None
        try:
            data = self._serializer.loads(token, max_age=self.max_age)
        except BadSignature:
            return None
        if not isinstance(data, dict) or data.get("role") not in {"admin", "tenant"}:
            return None
        return data


class RateLimiter:
    """Ventana deslizante en memoria: máx. `limit` fallos por clave en `window` s."""

    def __init__(self, limit: int, window: int) -> None:
        self.limit, self.window = limit, window
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        q = self._hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._prune(key, time.monotonic())) >= self.limit

    def hit(self, key: str) -> None:
        with self._lock:
            now = time.monotonic()
            self._prune(key, now).append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

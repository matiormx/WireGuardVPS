"""Copias de seguridad cifradas de la plataforma.

Toda la plataforma vive en la base de datos (clientes, dispositivos y sus claves,
la clave privada del servidor, dominios, DNS, servicios, filtros, llaves…), así
que una copia es una instantánea consistente de SQLite más unos metadatos.

Formato del archivo (.wgpb):
    MAGIC | sal (16) | nonce (12) | AES-256-GCM( tar.gz{panel.db, meta.json} )
La clave se deriva de la frase de paso con scrypt. Sin la frase no se puede
restaurar: no hay puerta trasera.

Destinos: carpeta local (/data/backups, con retención) y, opcionalmente, un
almacenamiento compatible con S3 (AWS, Cloudflare R2, Backblaze B2, MinIO…).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .config import Settings
from .db import Database, get_setting, set_setting

log = logging.getLogger("wgp.backup")

MAGIC = b"WGPBAK1\n"
NAME_RE = re.compile(r"^wgp-\d{8}-\d{6}\.wgpb$")
FORMAT = 1
# Ajustes de red que deben coincidir para que las claves y configuraciones restauradas sigan valiendo.
NETWORK_KEYS = ("WG_SUBNET", "WG_SERVER_ADDRESS", "TENANT_PREFIX", "WG_PORT")

DEFAULTS = {
    "backup_enabled": "0",
    "backup_hour": "3",
    "backup_keep": "14",
    "s3_endpoint": "",
    "s3_region": "auto",
    "s3_bucket": "",
    "s3_prefix": "wireguard-cloud/",
    "s3_access_key": "",
    "s3_secret_key": "",
}


class BackupError(Exception):
    pass


# ---------------------------------------------------------------------- cifrado
def _key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode())


def encrypt(plain: bytes, passphrase: str) -> bytes:
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    header = MAGIC + salt
    return header + nonce + AESGCM(_key(passphrase, salt)).encrypt(nonce, plain, header)


def decrypt(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 28 + 16:
        raise BackupError("No es una copia de seguridad de WireGuard Cloud")
    salt = blob[len(MAGIC):len(MAGIC) + 16]
    nonce = blob[len(MAGIC) + 16:len(MAGIC) + 28]
    try:
        return AESGCM(_key(passphrase, salt)).decrypt(nonce, blob[len(MAGIC) + 28:], MAGIC + salt)
    except Exception:  # InvalidTag
        raise BackupError("Frase de paso incorrecta o archivo dañado") from None


# ---------------------------------------------------------------------- contenido
def network_meta(settings: Settings) -> dict:
    return {
        "WG_SUBNET": str(settings.wg_subnet),
        "WG_SERVER_ADDRESS": str(settings.server_address),
        "TENANT_PREFIX": str(settings.tenant_prefix),
        "WG_PORT": str(settings.wg_port),
    }


def snapshot(db_path: Path) -> bytes:
    """Copia consistente de SQLite (API de backup: válida aunque el panel esté escribiendo)."""
    with tempfile.TemporaryDirectory(dir=db_path.parent) as tmp:
        dest = Path(tmp) / "panel.db"
        src = sqlite3.connect(db_path)
        try:
            out = sqlite3.connect(dest)
            with out:
                src.backup(out)
            out.close()
        finally:
            src.close()
        return dest.read_bytes()


def build_archive(db_bytes: bytes, meta: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in (("meta.json", json.dumps(meta, indent=2).encode()), ("panel.db", db_bytes)):
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), int(time.time()), 0o600
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def open_archive(blob: bytes, passphrase: str) -> tuple[dict, bytes]:
    plain = decrypt(blob, passphrase)
    try:
        with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
            meta = json.loads(tar.extractfile("meta.json").read())  # type: ignore[union-attr]
            db_bytes = tar.extractfile("panel.db").read()  # type: ignore[union-attr]
    except (tarfile.TarError, KeyError, AttributeError, ValueError) as exc:
        raise BackupError(f"Contenido de la copia no válido: {exc}") from None
    if meta.get("format") != FORMAT:
        raise BackupError(f"Formato de copia no soportado: {meta.get('format')}")
    if not db_bytes.startswith(b"SQLite format 3\x00"):
        raise BackupError("La copia no contiene una base de datos válida")
    return meta, db_bytes


def summarize(db_bytes: bytes) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        f.write(db_bytes)
        f.flush()
        c = sqlite3.connect(f.name)
        try:
            count = lambda table: c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: E731
            settings = dict(c.execute("SELECT key, value FROM settings").fetchall())
            return {"tenants": count("tenants"), "devices": count("devices"),
                    "endpoint": settings.get("wg_endpoint", ""), "main_domain": settings.get("main_domain", "")}
        finally:
            c.close()


# ---------------------------------------------------------------------- S3 (firma SigV4, sin dependencias)
def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def s3_sign(cfg: dict, method: str, key: str, data: bytes = b"", now: dt.datetime | None = None) -> tuple[str, dict]:
    """URL y cabeceras firmadas (AWS Signature V4, path-style) para S3 y compatibles."""
    endpoint = cfg["s3_endpoint"].rstrip("/")
    if "://" not in endpoint:
        endpoint = "https://" + endpoint
    url = urllib.parse.urlsplit(endpoint)
    region = cfg.get("s3_region") or "auto"
    now = now or dt.datetime.now(dt.timezone.utc)
    amz_date, datestamp = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    path = f"{url.path.rstrip('/')}/{urllib.parse.quote(cfg['s3_bucket'], safe='')}/{urllib.parse.quote(key, safe='/-_.~')}"
    payload_hash = hashlib.sha256(data).hexdigest()
    headers = {"host": url.netloc, "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date}
    signed = ";".join(sorted(headers))
    canonical = "\n".join([method, path, "", *(f"{k}:{headers[k]}" for k in sorted(headers)), "", signed, payload_hash])
    scope = f"{datestamp}/{region}/s3/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = _sign(("AWS4" + cfg["s3_secret_key"]).encode(), datestamp)
    for part in (region, "s3", "aws4_request"):
        k = _sign(k, part)
    signature = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = (f"AWS4-HMAC-SHA256 Credential={cfg['s3_access_key']}/{scope}, "
                                f"SignedHeaders={signed}, Signature={signature}")
    del headers["host"]
    return f"{url.scheme}://{url.netloc}{path}", headers


def s3_request(cfg: dict, method: str, key: str, data: bytes = b"") -> bytes:
    url, headers = s3_sign(cfg, method, key, data)
    headers["content-type"] = "application/octet-stream"  # urllib pondría x-www-form-urlencoded
    req = urllib.request.Request(url, data=data if method == "PUT" else None, method=method, headers=headers)
    opener = urllib.request.build_opener()  # respeta HTTPS_PROXY si el servidor lo necesita
    try:
        with opener.open(req, timeout=60) as res:
            return res.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        code = re.search(r"<Code>([^<]+)</Code>", body)
        raise BackupError(f"S3 respondió {exc.code}{f' ({code.group(1)})' if code else ''}") from None
    except (OSError, ValueError) as exc:
        raise BackupError(f"No se pudo conectar con S3: {exc}") from None


def s3_configured(cfg: dict) -> bool:
    return all(cfg.get(k) for k in ("s3_endpoint", "s3_bucket", "s3_access_key", "s3_secret_key"))


# ---------------------------------------------------------------------- gestor
class Backups:
    def __init__(self, settings: Settings, database: Database) -> None:
        self.settings = settings
        self.db = database
        self.dir = settings.data_dir / "backups"
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self.on_failure = None  # callback(error): avisos a los administradores
        self._notified_day: str | None = None

    # ---- configuración
    def config(self) -> dict:
        with self.db.conn() as c:
            cfg = {k: get_setting(c, k) or v for k, v in DEFAULTS.items()}
            cfg["passphrase"] = get_setting(c, "backup_passphrase") or ""
            last = get_setting(c, "backup_last")
        cfg["last"] = json.loads(last) if last else None
        return cfg

    def save_config(self, values: dict) -> None:
        with self.db.conn() as c:
            for k, v in values.items():
                if k in DEFAULTS or k == "backup_passphrase":
                    set_setting(c, k, str(v))

    # ---- archivos locales
    def list(self) -> list[dict]:
        if not self.dir.is_dir():
            return []
        out = []
        for p in sorted(self.dir.iterdir(), reverse=True):
            if NAME_RE.match(p.name):
                st = p.stat()
                out.append({"name": p.name, "size": st.st_size, "created_at": int(st.st_mtime)})
        return out

    def path(self, name: str) -> Path:
        if not NAME_RE.match(name) or not (self.dir / name).is_file():
            raise BackupError("Copia no encontrada")
        return self.dir / name

    def prune(self, keep: int) -> None:
        for item in self.list()[max(1, keep):]:
            (self.dir / item["name"]).unlink(missing_ok=True)

    # ---- crear
    def create(self, reason: str = "manual") -> dict:
        cfg = self.config()
        if len(cfg["passphrase"]) < 12:
            raise BackupError("Define primero la frase de paso de las copias (mínimo 12 caracteres)")
        now = dt.datetime.now(dt.timezone.utc)
        meta = {"format": FORMAT, "created_at": int(now.timestamp()), "reason": reason, "network": network_meta(self.settings)}
        blob = encrypt(build_archive(snapshot(self.settings.data_dir / "panel.db"), meta), cfg["passphrase"])
        name = now.strftime("wgp-%Y%m%d-%H%M%S.wgpb")
        self.dir.mkdir(mode=0o700, exist_ok=True)
        tmp = self.dir / f".{name}.tmp"
        tmp.write_bytes(blob)
        os.chmod(tmp, 0o600)
        tmp.replace(self.dir / name)
        self.prune(int(cfg["backup_keep"]))
        result = {"at": meta["created_at"], "name": name, "size": len(blob), "ok": True, "error": None, "s3": None}
        if s3_configured(cfg):
            key = f"{cfg['s3_prefix'].strip('/')}/{name}".lstrip("/")
            try:
                s3_request(cfg, "PUT", key, blob)
                result["s3"] = key
            except BackupError as exc:
                result.update(ok=False, error=f"Copia local creada, pero falló la subida: {exc}")
        self._record(result)
        log.info("Copia de seguridad %s (%s, %d bytes)%s", name, reason, len(blob), f" -> S3 {result['s3']}" if result["s3"] else "")
        return result

    def _record(self, result: dict) -> None:
        with self.db.conn() as c:
            set_setting(c, "backup_last", json.dumps(result))

    def test_s3(self, cfg: dict) -> None:
        key = f"{cfg['s3_prefix'].strip('/')}/.wgp-test".lstrip("/")
        s3_request(cfg, "PUT", key, b"ok")
        try:
            s3_request(cfg, "DELETE", key)
        except BackupError:
            pass  # algunos permisos sólo permiten escribir: basta con eso

    # ---- programación diaria
    def due(self, now: dt.datetime | None = None) -> bool:
        cfg = self.config()
        if cfg["backup_enabled"] != "1" or len(cfg["passphrase"]) < 12:
            return False
        now = now or dt.datetime.now()
        if now.hour < int(cfg["backup_hour"]):
            return False
        today = now.replace(hour=int(cfg["backup_hour"]), minute=0, second=0, microsecond=0).timestamp()
        last = cfg["last"]
        # Tras un fallo se reintenta como mucho cada hora.
        if last and last["at"] >= today and (last["ok"] or time.time() - last["at"] < 3600):
            return False
        return True

    async def run_now(self, reason: str = "manual") -> dict:
        async with self._lock:
            return await asyncio.to_thread(self.create, reason)

    async def run(self) -> None:
        while True:
            await asyncio.sleep(60)
            error = None
            try:
                if await asyncio.to_thread(self.due):
                    result = await self.run_now("automática")
                    error = result["error"]
            except BackupError as exc:
                log.error("Copia automática fallida: %s", exc)
                error = str(exc)
                self._record({"at": int(time.time()), "name": None, "size": 0, "ok": False, "error": error, "s3": None})
            except Exception:  # noqa: BLE001 - el bucle no debe morir
                log.exception("Error inesperado en la copia automática")
            self._notify(error)

    def _notify(self, error: str | None) -> None:
        """Un aviso por día como mucho (los reintentos son cada hora)."""
        today = dt.date.today().isoformat()
        if error and self.on_failure and self._notified_day != today:
            self._notified_day = today
            try:
                self.on_failure(error)
            except Exception:  # noqa: BLE001
                log.exception("No se pudo avisar del fallo de la copia")

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.ensure_future(self.run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()


# ---------------------------------------------------------------------- restaurar (CLI, con el panel parado)
def restore(settings: Settings, blob: bytes, passphrase: str, force: bool = False) -> dict:
    meta, db_bytes = open_archive(blob, passphrase)
    current = network_meta(settings)
    diff = {k: (meta["network"].get(k), current[k]) for k in NETWORK_KEYS if meta["network"].get(k) != current[k]}
    if diff and not force:
        raise BackupError("La red de la copia no coincide con la de este servidor: " +
                          ", ".join(f"{k}={a} (aquí {b})" for k, (a, b) in diff.items()))
    db_path = settings.data_dir / "panel.db"
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        keep = db_path.with_name(f"panel.db.pre-restore-{int(time.time())}")
        src = sqlite3.connect(db_path)
        try:
            out = sqlite3.connect(keep)
            with out:
                src.backup(out)
            out.close()
        finally:
            src.close()
        os.chmod(keep, 0o600)
    tmp = db_path.with_name("panel.db.restore-tmp")
    tmp.write_bytes(db_bytes)
    os.chmod(tmp, 0o600)
    for suffix in ("-wal", "-shm"):
        Path(str(db_path) + suffix).unlink(missing_ok=True)
    tmp.replace(db_path)
    return {"meta": meta, **summarize(db_bytes)}

"""Marca de la plataforma: nombre de la aplicación y logo (Ajustes › Marca).

El logo se sube ya convertido: el navegador del administrador genera los PNG de
cada tamaño (icono normal, «maskable» de Android, icono de iOS y favicon) con un
canvas, así el servidor no necesita librerías de imagen. Aquí sólo se valida que
cada fichero sea un PNG del tamaño esperado y se guarda en la base de datos (así
entra en las copias de seguridad).

Se sirven en /brand/<fichero> sin sesión (hacen falta en el login). Sin logo
propio, /brand/* devuelve los iconos por defecto de /static.

Sin `from __future__ import annotations`: FastAPI evalúa las dependencias de `deps`.
"""
import base64
import binascii
import re
import sqlite3
import struct
import time
from pathlib import Path
from typing import Optional

from fastapi import HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .db import get_setting, set_setting

DEFAULT_NAME = "WireGuard Cloud"
DEFAULT_SHORT = "WG Cloud"
# fichero -> lado en píxeles
FILES = {"icon-192.png": 192, "icon-512.png": 512, "icon-maskable-512.png": 512, "apple-touch-icon.png": 180, "favicon.png": 64}
FALLBACK = {"icon-192.png": "icons/icon-192.png", "icon-512.png": "icons/icon-512.png",
            "icon-maskable-512.png": "icons/icon-maskable-512.png", "apple-touch-icon.png": "icons/apple-touch-icon.png",
            "favicon.png": "favicon.svg", "logo": "favicon.svg"}
MAX_BYTES = 700 * 1024
PNG_SIG = b"\x89PNG\r\n\x1a\n"
COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def name(c: sqlite3.Connection) -> str:
    return get_setting(c, "brand_name") or DEFAULT_NAME


def short_name(c: sqlite3.Connection) -> str:
    return get_setting(c, "brand_short") or (DEFAULT_SHORT if not get_setting(c, "brand_name") else name(c)[:12])


def version(c: sqlite3.Connection) -> str:
    return get_setting(c, "brand_version") or "2"


def has_logo(c: sqlite3.Connection) -> bool:
    return c.execute("SELECT 1 FROM brand_files WHERE name = 'icon-512.png'").fetchone() is not None


def url(c: sqlite3.Connection, file: str = "logo") -> str:
    return f"/brand/{file}?v={version(c)}"


def png_size(data: bytes) -> Optional[tuple]:
    if len(data) < 24 or not data.startswith(PNG_SIG) or data[12:16] != b"IHDR":
        return None
    return struct.unpack(">II", data[16:24])


class BrandIn(BaseModel):
    name: Optional[str] = Field(default=None, max_length=40)
    short_name: Optional[str] = Field(default=None, max_length=12)


class LogoIn(BaseModel):
    files: dict[str, str]
    background: str = "#0b0d14"


def register(app, d) -> None:
    static_dir: Path = d.static_dir

    def state(c: sqlite3.Connection) -> dict:
        return {"name": name(c), "short_name": short_name(c), "custom_logo": has_logo(c), "version": version(c),
                "background": get_setting(c, "brand_background") or "#0b0d14", "default_name": DEFAULT_NAME}

    def bump(c: sqlite3.Connection) -> None:
        set_setting(c, "brand_version", str(int(time.time())))

    @app.get("/api/admin/brand")
    def get_brand(_: d.Admin, c: d.Conn):
        return state(c)

    @app.put("/api/admin/brand")
    def put_brand(body: BrandIn, _: d.Admin, c: d.Conn):
        if body.name is not None:
            value = " ".join(body.name.split())
            if not value:
                raise HTTPException(422, "Escribe el nombre de la aplicación")
            set_setting(c, "brand_name", value)
        if body.short_name is not None:
            set_setting(c, "brand_short", " ".join(body.short_name.split()))
        bump(c)   # el manifest y el título de la app instalada cambian
        return state(c)

    @app.put("/api/admin/brand/logo")
    def put_logo(body: LogoIn, _: d.Admin, c: d.Conn):
        if set(body.files) != set(FILES):
            raise HTTPException(422, "Faltan tamaños del logo")
        if not COLOR_RE.match(body.background):
            raise HTTPException(422, "Color de fondo no válido")
        blobs = {}
        for fname, side in FILES.items():
            raw = body.files[fname].split(",", 1)[-1]          # admite «data:image/png;base64,…»
            try:
                data = base64.b64decode(raw, validate=True)
            except (binascii.Error, ValueError):
                raise HTTPException(422, f"{fname}: no es base64 válido")
            if len(data) > MAX_BYTES:
                raise HTTPException(413, f"{fname}: demasiado grande")
            if png_size(data) != (side, side):
                raise HTTPException(422, f"{fname}: debe ser un PNG de {side}×{side}")
            blobs[fname] = data
        now = int(time.time())
        c.executemany("INSERT OR REPLACE INTO brand_files (name, data, updated_at) VALUES (?, ?, ?)",
                      [(k, v, now) for k, v in blobs.items()])
        set_setting(c, "brand_background", body.background.lower())
        bump(c)
        return state(c)

    @app.delete("/api/admin/brand/logo")
    def delete_logo(_: d.Admin, c: d.Conn):
        c.execute("DELETE FROM brand_files")
        bump(c)
        return state(c)

    @app.get("/brand/{file}", include_in_schema=False)
    def brand_file(file: str, request: Request, c: d.Conn):
        if file not in FALLBACK:
            raise HTTPException(404)
        row = c.execute("SELECT data, updated_at FROM brand_files WHERE name = ?",
                        ("icon-512.png" if file == "logo" else file,)).fetchone()
        headers = {"Cache-Control": "public, max-age=31536000, immutable" if request.query_params.get("v") else "no-cache",
                   "X-Content-Type-Options": "nosniff"}
        if row is None:
            return FileResponse(static_dir / FALLBACK[file], headers=headers)
        etag = f'"{row["updated_at"]}"'
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers={**headers, "ETag": etag})
        return Response(row["data"], media_type="image/png", headers={**headers, "ETag": etag})

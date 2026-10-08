"""Utilidades de línea de comandos (dentro del contenedor).

  python -m app.cli reset-admin [--username U] [--password P]
"""
from __future__ import annotations

import argparse
import secrets
import sys
import time

from . import security, wg
from .config import load_settings
from .db import Database


def reset_admin(username: str | None, password: str | None) -> int:
    settings = load_settings()
    db = Database(settings.data_dir / "panel.db")
    db.init(settings.admin_user, settings.admin_password, wg.generate_keypair)
    password = password or secrets.token_urlsafe(12)
    with db.conn() as c:
        row = c.execute("SELECT id, username FROM admins ORDER BY id LIMIT 1").fetchone()
        username = username or row["username"]
        if c.execute("SELECT 1 FROM tenants WHERE username = ? COLLATE NOCASE", (username,)).fetchone():
            print(f"'{username}' ya es un usuario de cliente", file=sys.stderr)
            return 1
        c.execute(
            "UPDATE admins SET username = ?, password_hash = ?, must_change = 1, created_at = ? WHERE id = ?",
            (username, security.hash_password(password), int(time.time()), row["id"]),
        )
    print(f"Administrador: {username}\nContraseña temporal: {password}\n(se pedirá cambiarla al entrar)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("reset-admin", help="Restablece las credenciales del administrador")
    p.add_argument("--username")
    p.add_argument("--password")
    args = parser.parse_args(argv)
    if args.cmd == "reset-admin":
        return reset_admin(args.username, args.password)
    return 2


if __name__ == "__main__":
    sys.exit(main())

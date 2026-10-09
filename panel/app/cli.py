"""Utilidades de línea de comandos (dentro del contenedor).

  python -m app.cli reset-admin [--username U] [--password P]
  python -m app.cli backup                      Copia cifrada ahora (en /data/backups)
  python -m app.cli inspect ARCHIVO [--env]     Muestra el contenido de una copia
  python -m app.cli restore ARCHIVO [--force]   Restaura una copia (con el panel parado)

La frase de paso se lee de WGP_BACKUP_PASSPHRASE o se pide por teclado.
"""
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import os
import secrets
import sys
import time

from . import backup, security, wg
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


def _passphrase() -> str:
    value = os.environ.get("WGP_BACKUP_PASSPHRASE")
    if value:
        return value
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass("Frase de paso de la copia: ")


def cmd_backup() -> int:
    settings = load_settings()
    db = Database(settings.data_dir / "panel.db")
    try:
        r = backup.Backups(settings, db).create("cli")
    except backup.BackupError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Copia creada: {settings.data_dir / 'backups' / r['name']} ({r['size']} bytes)")
    if r["s3"]:
        print(f"Subida a S3: {r['s3']}")
    if r["error"]:
        print(r["error"], file=sys.stderr)
    return 0


def cmd_inspect(path: str, as_env: bool) -> int:
    try:
        meta, db_bytes = backup.open_archive(open(path, "rb").read(), _passphrase())
    except (OSError, backup.BackupError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if as_env:
        for key in backup.NETWORK_KEYS:
            print(f"{key}={meta['network'][key]}")
        return 0
    info = backup.summarize(db_bytes)
    when = dt.datetime.fromtimestamp(meta["created_at"]).strftime("%Y-%m-%d %H:%M")
    print(f"Copia del {when} ({meta.get('reason', '')})")
    print(f"  Clientes: {info['tenants']}  ·  Dispositivos: {info['devices']}")
    print(f"  Red: {meta['network']['WG_SUBNET']}  ·  Puerto WireGuard: {meta['network']['WG_PORT']}")
    print(f"  Endpoint: {info['endpoint'] or '(IP del servidor)'}  ·  Dominio del panel: {info['main_domain'] or '-'}")
    return 0


def cmd_restore(path: str, force: bool) -> int:
    settings = load_settings()
    try:
        r = backup.restore(settings, open(path, "rb").read(), _passphrase(), force=force)
    except (OSError, backup.BackupError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Restaurado: {r['tenants']} clientes y {r['devices']} dispositivos.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("reset-admin", help="Restablece las credenciales del administrador")
    p.add_argument("--username")
    p.add_argument("--password")
    sub.add_parser("backup", help="Crea una copia cifrada ahora")
    p = sub.add_parser("inspect", help="Muestra el contenido de una copia")
    p.add_argument("archivo")
    p.add_argument("--env", action="store_true", help="Sólo los ajustes de red (KEY=VALOR)")
    p = sub.add_parser("restore", help="Restaura una copia (con el panel parado)")
    p.add_argument("archivo")
    p.add_argument("--force", action="store_true", help="Restaurar aunque la red no coincida")
    args = parser.parse_args(argv)
    if args.cmd == "reset-admin":
        return reset_admin(args.username, args.password)
    if args.cmd == "backup":
        return cmd_backup()
    if args.cmd == "inspect":
        return cmd_inspect(args.archivo, args.env)
    if args.cmd == "restore":
        return cmd_restore(args.archivo, args.force)
    return 2


if __name__ == "__main__":
    sys.exit(main())

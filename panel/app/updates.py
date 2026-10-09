"""Actualizaciones de la plataforma desde el panel (Ajustes › Actualizaciones).

El panel corre en un contenedor y no puede actualizar el host. Se comunica con
él mediante ficheros en /etc/wireguard/wgp (montado en el contenedor):

  * version.json   lo escribe «wg-manager» al instalar/actualizar (versión, commit…)
  * update.request lo escribe el panel; la unidad wgp-update.path lo detecta y
                   ejecuta siempre lo mismo: «wg-manager update»
  * update.status  estado de la última actualización (running/done/failed)
  * update.log     salida de esa actualización

La versión disponible se lee del propio script publicado (VERSION="x.y.z"),
igual que hace la auto-actualización de wg-manager.

Actualización automática: un día de la semana (o todos) a una hora; sólo si hay
una versión nueva. Durante la actualización el panel se reinicia unos segundos;
los túneles WireGuard no se cortan.

Sin `from __future__ import annotations`: FastAPI evalúa las dependencias de `deps`.
"""
import asyncio
import datetime as dt
import json
import logging
import os
import re
import time
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field

from .config import Settings
from .db import Database, get_setting, set_setting

log = logging.getLogger("wgp.updates")

DEFAULT_URL = "https://raw.githubusercontent.com/matiormx/WireGuardVps/main/wg-manager.sh"
VERSION_RE = re.compile(r'^(?:readonly\s+)?VERSION="([^"]+)"', re.M)
CHECK_TTL = 6 * 3600          # la comprobación en segundo plano, como mucho cada 6 h
QUEUE_TIMEOUT = 180           # si el host no recoge la petición en 3 min, algo falla
RUN_TIMEOUT = 50 * 60         # una actualización «running» más vieja que esto se da por perdida
DAYS = ["daily", "0", "1", "2", "3", "4", "5", "6"]   # 0 = lunes


def parse_version(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3]) or (0,)


def newer(remote: Optional[str], local: Optional[str]) -> bool:
    return bool(remote and local) and parse_version(remote) > parse_version(local)


def _read_json(path: Path) -> Optional[dict]:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


class Updates:
    def __init__(self, settings: Settings, db: Database, notify: Optional[Callable[[str, str], None]] = None):
        self.dir = settings.wg_conf_dir / "wgp"
        self.db = db
        self.notify = notify
        self.url = os.environ.get("WGP_SCRIPT_URL") or DEFAULT_URL
        self._task: Optional[asyncio.Task] = None

    # ---- estado del host
    def installed(self) -> Optional[dict]:
        return _read_json(self.dir / "version.json")

    def ready(self) -> bool:
        info = self.installed()
        return bool(info and info.get("updater"))

    def host_status(self) -> Optional[dict]:
        return _read_json(self.dir / "update.status")

    def log_tail(self, lines: int = 200) -> str:
        try:
            text = (self.dir / "update.log").read_text(errors="replace")
        except OSError:
            return ""
        text = re.sub(r"\x1b\[[0-9;]*m", "", text)   # sin colores de la terminal
        return "\n".join(text.splitlines()[-lines:])

    def status(self, now: Optional[float] = None) -> dict:
        """Estado combinado: la petición pendiente del panel y lo que informa el host."""
        now = now or time.time()
        st = self.host_status() or {}
        with self.db.conn() as c:
            req = json.loads(get_setting(c, "update_request") or "null")
        if req and req["at"] > (st.get("started_at") or 0):
            # Pedida y el host aún no la ha empezado
            state = "queued" if now - req["at"] < QUEUE_TIMEOUT else "stuck"
            return {"state": state, "requested_at": req["at"], "reason": req.get("reason")}
        if st.get("state") == "running" and now - st.get("started_at", 0) > RUN_TIMEOUT:
            st = {**st, "state": "lost"}
        return {**st, "state": st.get("state", "idle"), "reason": (req or {}).get("reason")}

    def running(self) -> bool:
        return self.status()["state"] in ("queued", "running")

    # ---- versión publicada
    def fetch_remote(self) -> str:
        req = urllib.request.Request(self.url, headers={"Cache-Control": "no-cache", "User-Agent": "wgp-panel"})
        with urllib.request.urlopen(req, timeout=20) as r:   # noqa: S310 - URL fija de la instalación
            head = r.read(256 * 1024).decode("utf-8", "replace")
        m = VERSION_RE.search(head)
        if not m:
            raise ValueError("No se encontró VERSION en el script publicado")
        return m.group(1)

    def check(self) -> dict:
        try:
            result = {"version": self.fetch_remote(), "checked_at": int(time.time()), "error": None}
        except Exception as exc:  # noqa: BLE001 - red, DNS, GitHub caído…
            log.warning("No se pudo comprobar la versión publicada: %s", exc)
            result = {"version": None, "checked_at": int(time.time()), "error": f"No se pudo consultar la versión publicada ({exc})"}
        with self.db.conn() as c:
            prev = json.loads(get_setting(c, "update_remote") or "null") or {}
            if not result["version"] and prev.get("version"):
                result["version"] = prev["version"]   # se conserva la última conocida
            set_setting(c, "update_remote", json.dumps(result))
        return result

    def remote(self) -> dict:
        with self.db.conn() as c:
            return json.loads(get_setting(c, "update_remote") or "null") or {"version": None, "checked_at": None, "error": None}

    # ---- pedir la actualización al host
    def request(self, reason: str) -> None:
        if not self.ready():
            raise HTTPException(409, "El actualizador del servidor no está instalado: ejecuta una vez «sudo wg-manager update»")
        if self.running():
            raise HTTPException(409, "Ya hay una actualización en marcha")
        now = int(time.time())
        self.dir.mkdir(parents=True, exist_ok=True)
        # Escritura directa (como apply.stamp): el cierre del fichero dispara wgp-update.path
        with open(self.dir / "update.request", "w") as fh:
            fh.write(json.dumps({"at": now, "reason": reason}) + "\n")
        with self.db.conn() as c:
            set_setting(c, "update_request", json.dumps({"at": now, "reason": reason}))
        log.info("Actualización solicitada (%s)", reason)

    # ---- programación
    def auto(self) -> dict:
        with self.db.conn() as c:
            return {
                "enabled": get_setting(c, "update_auto") == "1",
                "day": get_setting(c, "update_day") or "daily",
                "hour": int(get_setting(c, "update_hour") or 4),
            }

    def set_auto(self, enabled: bool, day: str, hour: int) -> None:
        with self.db.conn() as c:
            set_setting(c, "update_auto", "1" if enabled else "0")
            set_setting(c, "update_day", day)
            set_setting(c, "update_hour", str(hour))

    def due(self, now: Optional[dt.datetime] = None) -> bool:
        """¿Toca la actualización automática? Una vez por día programado, a partir de la hora."""
        cfg = self.auto()
        if not cfg["enabled"] or not self.ready():
            return False
        now = now or dt.datetime.now()
        if cfg["day"] != "daily" and str(now.weekday()) != cfg["day"]:
            return False
        if now.hour < cfg["hour"]:
            return False
        with self.db.conn() as c:
            return get_setting(c, "update_auto_last") != now.date().isoformat()

    def tick(self, now: Optional[dt.datetime] = None) -> Optional[str]:
        """Un paso del bucle. Devuelve lo que ha hecho (para los tests)."""
        done = self._notify_finished()
        now = now or dt.datetime.now()
        if self.due(now):
            with self.db.conn() as c:
                set_setting(c, "update_auto_last", now.date().isoformat())
            remote = self.check()
            local = (self.installed() or {}).get("version")
            if remote["version"] and newer(remote["version"], local) and not self.running():
                self.request("automática")
                return "requested"
            return "up-to-date"
        if time.time() - (self.remote().get("checked_at") or 0) > CHECK_TTL:
            self.check()
            return "checked"
        return done

    def _notify_finished(self) -> Optional[str]:
        """Aviso a los administradores cuando termina una actualización (una vez)."""
        st = self.host_status() or {}
        fin = st.get("finished_at")
        if not fin or st.get("state") not in ("done", "failed"):
            return None
        with self.db.conn() as c:
            if int(get_setting(c, "update_notified") or 0) >= fin:
                return None
            set_setting(c, "update_notified", str(fin))
            req = json.loads(get_setting(c, "update_request") or "null") or {}
        if not self.notify:
            return "finished"
        auto = " automática" if req.get("reason") == "automática" else ""
        if st["state"] == "done":
            title, body = f"✅ Servidor actualizado a v{st.get('version') or '?'}", f"La actualización{auto} terminó correctamente."
        else:
            title, body = "⚠️ La actualización del servidor ha fallado", (
                f"La actualización{auto} terminó con código {st.get('exit_code')}. Revisa el registro en Ajustes › Actualizaciones.")
        try:
            self.notify(title, body)
        except Exception:  # noqa: BLE001
            log.exception("No se pudo avisar del resultado de la actualización")
        return "finished"

    async def run(self) -> None:
        await asyncio.sleep(20)   # deja arrancar el panel antes de la primera comprobación
        while True:
            try:
                await asyncio.to_thread(self.tick)
            except Exception:  # noqa: BLE001 - el bucle no debe morir
                log.exception("Error en la comprobación de actualizaciones")
            await asyncio.sleep(60)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.ensure_future(self.run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    # ---- respuesta de la API
    def view(self) -> dict:
        info = self.installed() or {}
        remote = self.remote()
        return {
            "current": info.get("version"),
            "commit": info.get("commit") or None,
            "updated_at": info.get("updated_at"),
            "branch": info.get("branch") or None,
            "ready": self.ready(),
            "latest": remote.get("version"),
            "checked_at": remote.get("checked_at"),
            "check_error": remote.get("error"),
            "available": newer(remote.get("version"), info.get("version")),
            "status": self.status(),
            "log": self.log_tail(),
            "auto": self.auto(),
            "timezone": time.strftime("%Z"),
        }


class AutoBody(BaseModel):
    enabled: bool
    day: str = Field("daily", pattern=r"^(daily|[0-6])$")
    hour: int = Field(4, ge=0, le=23)


def register(app, d) -> None:
    upd: Updates = d.updates
    Admin = d.Admin

    @app.get("/api/admin/update")
    def get_update(_: Admin):
        return upd.view()

    @app.post("/api/admin/update/check")
    async def check_update(_: Admin):
        await asyncio.to_thread(upd.check)
        return upd.view()

    @app.post("/api/admin/update/run")
    def run_update(_: Admin):
        upd.request("manual")
        return upd.view()

    @app.put("/api/admin/update/auto")
    def put_auto(body: AutoBody, _: Admin):
        upd.set_auto(body.enabled, body.day, body.hour)
        return upd.view()

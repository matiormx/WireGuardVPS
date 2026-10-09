"""Monitor del servidor: CPU, memoria, disco, carga y red, con historial y avisos.

El panel corre con `network_mode: host` y /proc del contenedor refleja el host
(CPU, memoria, carga, tiempo encendido e interfaces de red); el disco se mide
con statvfs sobre /etc/wireguard, que es del sistema de ficheros del host.

Muestras cada 10 s (en memoria, para el «ahora»), una fila por minuto
(sys_minute, 48 h) y una por hora (sys_hourly, 400 días).

Avisos a los administradores (preferencia «server»): disco ≥ 90 %, memoria
≥ 90 % durante 10 min y CPU ≥ 90 % durante 15 min; y cuando se recupera.

Sin `from __future__ import annotations`: FastAPI evalúa las dependencias de `deps`.
"""
import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Callable, Optional

from fastapi import HTTPException

from .db import Database, get_setting, set_setting

log = logging.getLogger("wgp.sysmon")

INTERVAL = 10
KEEP_MINUTES = 48 * 3600
KEEP_HOURS = 400 * 86400
FIELDS = ("cpu", "mem", "swap", "disk", "load1", "rx", "tx")
# rango -> (tabla, segundos por punto, número de puntos)
RANGES = {"1h": ("minute", 60, 60), "24h": ("minute", 300, 288), "7d": ("hour", 3600, 168), "30d": ("hour", 4 * 3600, 180)}
# (métrica, umbral, umbral de recuperación, minutos seguidos)
THRESHOLDS = {"disk": (90, 85, 1), "mem": (90, 80, 10), "cpu": (90, 75, 15)}
LABELS = {"disk": "Disco", "mem": "Memoria", "cpu": "CPU"}


class Sysmon:
    def __init__(self, db: Database, disk_path: Path, notify: Optional[Callable[[str, str], None]] = None,
                 proc: str = "/proc"):
        self.db = db
        self.disk_path = disk_path
        self.notify = notify
        self.proc = proc
        self.last: Optional[dict] = None        # última muestra instantánea
        self._prev: Optional[tuple] = None      # (ts, cpu_busy, cpu_total, rx, tx)
        self._acc: list = []                    # muestras del minuto en curso
        self._minute: Optional[int] = None
        self._task: Optional[asyncio.Task] = None

    # ---- lectura de /proc
    def _read(self, name: str) -> str:
        with open(os.path.join(self.proc, name)) as fh:
            return fh.read()

    def cpu_times(self) -> tuple:
        vals = [int(x) for x in self._read("stat").splitlines()[0].split()[1:]]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)        # idle + iowait
        total = sum(vals[:8])                                     # sin guest (ya incluido en user)
        return total - idle, total

    def memory(self) -> dict:
        info = {}
        for line in self._read("meminfo").splitlines():
            k, _, v = line.partition(":")
            info[k] = int(v.split()[0]) * 1024 if v.split() else 0
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0) + info.get("Cached", 0))
        return {"total": total, "used": max(0, total - avail),
                "swap_total": info.get("SwapTotal", 0), "swap_used": max(0, info.get("SwapTotal", 0) - info.get("SwapFree", 0))}

    def wan_iface(self) -> Optional[str]:
        try:
            for line in self._read("net/route").splitlines()[1:]:
                parts = line.split()
                if len(parts) > 2 and parts[1] == "00000000":
                    return parts[0]
        except OSError:
            pass
        return None

    def net_bytes(self, iface: Optional[str]) -> tuple:
        rx = tx = 0
        for line in self._read("net/dev").splitlines()[2:]:
            name, _, rest = line.partition(":")
            name = name.strip()
            if (iface and name != iface) or (not iface and (name == "lo" or name.startswith(("wg", "docker", "veth", "br-")))):
                continue
            f = rest.split()
            rx += int(f[0])
            tx += int(f[8])
        return rx, tx

    def disk(self) -> dict:
        path = Path(self.disk_path)
        while not path.exists() and path != path.parent:
            path = path.parent
        st = os.statvfs(path)
        used = (st.f_blocks - st.f_bfree) * st.f_frsize
        avail = st.f_bavail * st.f_frsize
        return {"total": st.f_blocks * st.f_frsize, "used": used, "free": avail,
                "pct": round(100 * used / (used + avail), 1) if used + avail else 0}

    def loadavg(self) -> list:
        return [float(x) for x in self._read("loadavg").split()[:3]]

    def uptime(self) -> int:
        return int(float(self._read("uptime").split()[0]))

    def cpu_model(self) -> str:
        try:
            for line in self._read("cpuinfo").splitlines():
                if line.lower().startswith(("model name", "hardware", "cpu model")):
                    return line.split(":", 1)[1].strip()
        except OSError:
            pass
        return ""

    # ---- muestreo
    def sample(self, now: Optional[float] = None) -> Optional[dict]:
        """Toma una muestra; devuelve los valores instantáneos (o None en la primera)."""
        now = now or time.time()
        busy, total = self.cpu_times()
        iface = self.wan_iface()
        rx, tx = self.net_bytes(iface)
        mem = self.memory()
        disk = self.disk()
        load = self.loadavg()
        prev, self._prev = self._prev, (now, busy, total, rx, tx)
        if not prev or now <= prev[0]:
            return None
        dt_ = now - prev[0]
        cur = {
            "ts": int(now),
            "cpu": round(100 * max(0, busy - prev[1]) / max(1, total - prev[2]), 1),
            "mem": round(100 * mem["used"] / mem["total"], 1) if mem["total"] else 0,
            "swap": round(100 * mem["swap_used"] / mem["swap_total"], 1) if mem["swap_total"] else 0,
            "disk": disk["pct"],
            "load1": load[0],
            "rx": max(0, rx - prev[3]) / dt_,     # bytes/s (contadores reiniciados -> 0)
            "tx": max(0, tx - prev[4]) / dt_,
            "load": load, "memory": mem, "disk_info": disk, "iface": iface,
        }
        self.last = cur
        minute = int(now // 60) * 60
        if self._minute is not None and minute != self._minute:
            self.flush()
        self._minute = minute
        self._acc.append(cur)
        return cur

    def flush(self) -> None:
        """Guarda la media del minuto en curso y, al cambiar de hora, el resumen horario."""
        if not self._acc or self._minute is None:
            return
        avg = {k: sum(s[k] for s in self._acc) / len(self._acc) for k in FIELDS}
        self._acc = []
        ts = self._minute
        with self.db.conn() as c:
            c.execute(f"INSERT OR REPLACE INTO sys_minute (ts, {', '.join(FIELDS)}) VALUES (?, {', '.join('?' * len(FIELDS))})",
                      (ts, *(round(avg[k], 2) for k in FIELDS)))
            self._rollup(c, ts // 3600 * 3600)
            last_hour = int(get_setting(c, "sysmon_hour") or 0)
            if last_hour and last_hour != ts // 3600 * 3600:
                self._rollup(c, last_hour)          # cierra la hora anterior con todos sus minutos
                c.execute("DELETE FROM sys_minute WHERE ts < ?", (ts - KEEP_MINUTES,))
                c.execute("DELETE FROM sys_hourly WHERE hour < ?", (ts - KEEP_HOURS,))
            set_setting(c, "sysmon_hour", str(ts // 3600 * 3600))
        self.check_alerts()

    @staticmethod
    def _rollup(c, hour: int) -> None:
        r = c.execute("""SELECT COUNT(*) AS n, AVG(cpu) AS cpu, MAX(cpu) AS cpu_max, AVG(mem) AS mem, MAX(mem) AS mem_max,
                                AVG(swap) AS swap, MAX(disk) AS disk, AVG(load1) AS load1, AVG(rx) AS rx, AVG(tx) AS tx
                         FROM sys_minute WHERE ts >= ? AND ts < ?""", (hour, hour + 3600)).fetchone()
        if r["n"]:
            c.execute("""INSERT OR REPLACE INTO sys_hourly (hour, cpu, cpu_max, mem, mem_max, swap, disk, load1, rx, tx)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                      (hour, *(round(r[k], 2) for k in ("cpu", "cpu_max", "mem", "mem_max", "swap", "disk", "load1", "rx", "tx"))))

    # ---- avisos
    def check_alerts(self) -> list:
        sent = []
        with self.db.conn() as c:
            active = json.loads(get_setting(c, "sysmon_alerts") or "{}")
            rows = c.execute("SELECT cpu, mem, disk FROM sys_minute ORDER BY ts DESC LIMIT 15").fetchall()
            changed = False
            for key, (high, low, minutes) in THRESHOLDS.items():
                recent = [r[key] for r in rows[:minutes]]
                if len(recent) < minutes:
                    continue
                value = sum(recent) / len(recent)
                if not active.get(key) and min(recent) >= high:
                    active[key] = True
                    changed = True
                    sent.append(self._alert(key, value, True))
                elif active.get(key) and value < low:
                    active[key] = False
                    changed = True
                    sent.append(self._alert(key, value, False))
            if changed:
                set_setting(c, "sysmon_alerts", json.dumps(active))
        return sent

    def _alert(self, key: str, value: float, raised: bool) -> str:
        label = LABELS[key]
        if raised:
            title = f"⚠️ {label} del servidor al {value:.0f} %"
            body = {"disk": "Libera espacio o amplía el disco: sin espacio fallan las copias, el registro y las actualizaciones.",
                    "mem": "La memoria lleva 10 minutos por encima del 90 %.",
                    "cpu": "La CPU lleva 15 minutos por encima del 90 %."}[key]
        else:
            title, body = f"🟢 {label} del servidor normal ({value:.0f} %)", "El uso ha vuelto a niveles normales."
        if self.notify:
            try:
                self.notify(title, body)
            except Exception:  # noqa: BLE001
                log.exception("No se pudo enviar el aviso del servidor")
        return title

    def alerts(self) -> dict:
        with self.db.conn() as c:
            return {k: v for k, v in json.loads(get_setting(c, "sysmon_alerts") or "{}").items() if v}

    # ---- consultas
    def history(self, rng: str, now: Optional[float] = None) -> dict:
        if rng not in RANGES:
            raise HTTPException(422, "Rango no válido")
        table, step, n = RANGES[rng]
        now = int(now or time.time())
        end = now // step * step
        start = end - (n - 1) * step
        with self.db.conn() as c:
            if table == "minute":
                rows = c.execute(f"""SELECT ts / ? * ? AS b, {', '.join(f'AVG({k}) AS {k}' for k in FIELDS)}, MAX(cpu) AS cpu_max, MAX(mem) AS mem_max
                                     FROM sys_minute WHERE ts >= ? GROUP BY b""", (step, step, start)).fetchall()
            else:
                rows = c.execute(f"""SELECT hour / ? * ? AS b, {', '.join(f'AVG({k}) AS {k}' for k in FIELDS if k != 'disk')},
                                            MAX(disk) AS disk, MAX(cpu_max) AS cpu_max, MAX(mem_max) AS mem_max
                                     FROM sys_hourly WHERE hour >= ? GROUP BY b""", (step, step, start)).fetchall()
        by = {r["b"]: r for r in rows}
        keys = (*FIELDS, "cpu_max", "mem_max")
        points = []
        for t in range(start, end + 1, step):
            r = by.get(t)
            points.append({"t": t, **{k: (round(r[k], 2) if r and r[k] is not None else None) for k in keys}})
        return {"range": rng, "step": step, "points": points}

    def live(self) -> dict:
        cur = self.last
        info = {"cores": os.cpu_count() or 1, "model": self.cpu_model(), "kernel": os.uname().release}
        try:
            info["uptime"] = self.uptime()
        except OSError:
            info["uptime"] = None
        if not cur:
            return {"ready": False, **info, "alerts": self.alerts()}
        return {
            "ready": True, **info, "ts": cur["ts"],
            "cpu": cur["cpu"], "load": cur["load"],
            "memory": {**cur["memory"], "pct": cur["mem"], "swap_pct": cur["swap"]},
            "disk": cur["disk_info"],
            "net": {"iface": cur["iface"], "rx": round(cur["rx"]), "tx": round(cur["tx"])},
            "alerts": self.alerts(),
        }

    # ---- bucle
    async def run(self) -> None:
        while True:
            try:
                await asyncio.to_thread(self.sample)
            except Exception:  # noqa: BLE001 - el bucle no debe morir
                log.exception("Error al muestrear el servidor")
            await asyncio.sleep(INTERVAL)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.ensure_future(self.run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
        try:
            self.flush()
        except Exception:  # noqa: BLE001
            pass


def register(app, d) -> None:
    mon: Sysmon = d.sysmon
    Admin = d.Admin

    @app.get("/api/admin/server/live")
    def server_live(_: Admin):
        info = mon.live()
        hostinfo = d.host_info()
        return {**info, "hostname": hostinfo.get("hostname"), "os": hostinfo.get("os")}

    @app.get("/api/admin/server/history")
    def server_history(_: Admin, range: str = "24h"):   # noqa: A002 - nombre del parámetro en la API
        return mon.history(range)

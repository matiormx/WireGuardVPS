"""Monitor: historial de tráfico, registro de conexiones, estadísticas DNS y eventos.

Cada minuto lee `wg show dump` y guarda en SQLite:
  * el tráfico de cada dispositivo por hora (8 días) y por día (2 años),
  * las conexiones y desconexiones (90 días) con la IP pública de origen,
  * las consultas y bloqueos DNS de cada cliente (por hora, día y dominio).

Los contadores de WireGuard son acumulados desde que se levantó la interfaz:
se guarda el último valor visto (también entre reinicios del panel) y se
suma la diferencia; si el contador baja (wg0 reiniciada) se cuenta desde 0.

Los cambios de estado de los dispositivos vigilados generan eventos para los
avisos (dispositivo caído tras unos minutos, y recuperado).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable

from .config import Settings
from .db import Database, get_setting
from .wg import ONLINE_WINDOW

log = logging.getLogger("wgp.monitor")

INTERVAL = 60
DEFAULT_ALERT_DELAY = 5  # minutos desconectado antes de avisar
KEEP_HOURLY = 8 * 86400
KEEP_DAILY_DAYS = 730
KEEP_EVENTS = 90 * 86400
KEEP_DNS_TOP_DAYS = 31


@dataclass
class Event:
    kind: str            # device_offline | device_online
    tenant_id: int
    tenant_name: str
    device_id: int
    device_name: str
    device_kind: str
    member_id: int | None
    ts: int
    downtime: int = 0    # segundos (device_online tras un aviso)
    extra: dict = field(default_factory=dict)


def day_of(ts: float) -> str:
    """Día local (zona horaria del servidor) de una marca de tiempo."""
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d")


def endpoint_ip(endpoint: str | None) -> str | None:
    if not endpoint:
        return None
    host = endpoint.rsplit(":", 1)[0]
    return host.strip("[]") or None


class Monitor:
    def __init__(self, settings: Settings, database: Database, wgm, dns=None) -> None:
        self.settings = settings
        self.db = database
        self.wgm = wgm
        self.dns = dns
        self.listeners: list[Callable[[list[Event]], None]] = []
        self._task: asyncio.Task | None = None
        self._last_prune = 0.0

    # ------------------------------------------------------------------ tráfico y estado
    def alert_delay(self, c) -> int:
        raw = get_setting(c, "alert_delay_min")
        return int(raw) * 60 if raw and raw.isdigit() else DEFAULT_ALERT_DELAY * 60

    def tick(self, now: float | None = None, stats: dict | None = None) -> list[Event]:
        now = time.time() if now is None else now
        if stats is None:
            if not self.wgm.interface_up():
                return []  # sin interfaz no hay datos: no se marcan todos como caídos
            stats = self.wgm.stats()
        hour, day = int(now // 3600), day_of(now)
        events: list[Event] = []
        with self.db.conn() as c:
            delay = self.alert_delay(c)
            devices = c.execute(
                """SELECT d.id, d.tenant_id, d.name, d.kind, d.public_key, d.enabled, d.monitor, d.member_id,
                          t.name AS tenant_name, t.enabled AS tenant_enabled
                   FROM devices d JOIN tenants t ON t.id = d.tenant_id"""
            ).fetchall()
            states = {r["device_id"]: r for r in c.execute("SELECT * FROM device_state")}
            for d in devices:
                st = stats.get(d["public_key"], {})
                rx, tx = int(st.get("rx", 0)), int(st.get("tx", 0))
                active = bool(d["enabled"]) and bool(d["tenant_enabled"])
                online = bool(st.get("online")) and active
                handshake = st.get("last_handshake")
                endpoint = endpoint_ip(st.get("endpoint"))
                prev = states.get(d["id"])
                if prev is None:
                    c.execute(
                        """INSERT INTO device_state (device_id, rx, tx, online, changed_at, last_seen, endpoint)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (d["id"], rx, tx, int(online), int(now), handshake, endpoint),
                    )
                    if online:
                        self._event_row(c, d, int(now), "online", endpoint)
                    continue

                drx = rx - prev["rx"] if rx >= prev["rx"] else rx
                dtx = tx - prev["tx"] if tx >= prev["tx"] else tx
                if drx or dtx:
                    for table, key in (("traffic_hourly", ("hour", hour)), ("traffic_daily", ("day", day))):
                        c.execute(
                            f"""INSERT INTO {table} (tenant_id, device_id, {key[0]}, rx, tx) VALUES (?, ?, ?, ?, ?)
                                ON CONFLICT(device_id, {key[0]}) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx""",
                            (d["tenant_id"], d["id"], key[1], drx, dtx),
                        )

                changed_at, alerted = prev["changed_at"], prev["alerted"]
                last_seen = handshake or prev["last_seen"]
                if online != bool(prev["online"]):
                    # La desconexión ocurrió al caducar el último handshake, no ahora.
                    ts = int(now) if online or not handshake else int(min(now, handshake + ONLINE_WINDOW))
                    ts = max(ts, changed_at)
                    self._event_row(c, d, ts, "online" if online else "offline", endpoint or prev["endpoint"])
                    if online and alerted:
                        events.append(self._event(d, "device_online", int(now), downtime=int(now) - changed_at))
                    changed_at, alerted = ts, 0
                elif (not online and active and d["monitor"] and not alerted and prev["last_seen"]
                      and now - changed_at >= delay):
                    events.append(self._event(d, "device_offline", int(now), extra={"since": changed_at}))
                    alerted = 1
                c.execute(
                    """UPDATE device_state SET rx = ?, tx = ?, online = ?, changed_at = ?, last_seen = ?,
                       endpoint = COALESCE(?, endpoint), alerted = ? WHERE device_id = ?""",
                    (rx, tx, int(online), changed_at, last_seen, endpoint, alerted, d["id"]),
                )
            c.execute("DELETE FROM device_state WHERE device_id NOT IN (SELECT id FROM devices)")
            if now - self._last_prune > 3600:
                self._prune(c, now)
                self._last_prune = now
        return events

    def _event_row(self, c, d, ts: int, kind: str, endpoint: str | None) -> None:
        c.execute("INSERT INTO conn_events (tenant_id, device_id, ts, kind, endpoint) VALUES (?, ?, ?, ?, ?)",
                  (d["tenant_id"], d["id"], ts, kind, endpoint))

    @staticmethod
    def _event(d, kind: str, ts: int, downtime: int = 0, extra: dict | None = None) -> Event:
        return Event(kind, d["tenant_id"], d["tenant_name"], d["id"], d["name"], d["kind"], d["member_id"], ts,
                     downtime, extra or {})

    def _prune(self, c, now: float) -> None:
        c.execute("DELETE FROM traffic_hourly WHERE hour < ?", (int((now - KEEP_HOURLY) // 3600),))
        c.execute("DELETE FROM dns_hourly WHERE hour < ?", (int((now - KEEP_HOURLY) // 3600),))
        c.execute("DELETE FROM traffic_daily WHERE day < ?", (day_of(now - KEEP_DAILY_DAYS * 86400),))
        c.execute("DELETE FROM dns_daily WHERE day < ?", (day_of(now - KEEP_DAILY_DAYS * 86400),))
        c.execute("DELETE FROM dns_top WHERE day < ?", (day_of(now - KEEP_DNS_TOP_DAYS * 86400),))
        c.execute("DELETE FROM conn_events WHERE ts < ?", (int(now - KEEP_EVENTS),))

    # ------------------------------------------------------------------ DNS
    def drain_dns(self) -> dict[int, tuple[dict[int, list[int]], Counter]]:
        """Recoge (en el hilo del bucle asyncio, donde escribe el resolver) lo pendiente de guardar."""
        if self.dns is None:
            return {}
        out = {}
        for tid, st in list(self.dns.stats.items()):
            hours, top = st.drain()
            if hours or top:
                out[tid] = (hours, top)
        return out

    def store_dns(self, pending: dict[int, tuple[dict[int, list[int]], Counter]], now: float | None = None) -> None:
        if not pending:
            return
        today = day_of(time.time() if now is None else now)
        with self.db.conn() as c:
            tenants = {r["id"] for r in c.execute("SELECT id FROM tenants")}
            for tid, (hours, top) in pending.items():
                if tid not in tenants:
                    continue
                for hour, (q, b) in hours.items():
                    c.execute("""INSERT INTO dns_hourly (tenant_id, hour, queries, blocked) VALUES (?, ?, ?, ?)
                                 ON CONFLICT(tenant_id, hour) DO UPDATE SET queries = queries + excluded.queries,
                                 blocked = blocked + excluded.blocked""", (tid, hour, q, b))
                    c.execute("""INSERT INTO dns_daily (tenant_id, day, queries, blocked) VALUES (?, ?, ?, ?)
                                 ON CONFLICT(tenant_id, day) DO UPDATE SET queries = queries + excluded.queries,
                                 blocked = blocked + excluded.blocked""", (tid, day_of(hour * 3600), q, b))
                for domain, n in top.items():
                    c.execute("""INSERT INTO dns_top (tenant_id, day, domain, count) VALUES (?, ?, ?, ?)
                                 ON CONFLICT(tenant_id, day, domain) DO UPDATE SET count = count + excluded.count""",
                              (tid, today, domain, n))

    # ------------------------------------------------------------------ bucle
    def emit(self, events: list[Event]) -> None:
        for fn in self.listeners:
            try:
                fn(events)
            except Exception:  # noqa: BLE001 - un aviso fallido no debe parar el monitor
                log.exception("Error entregando eventos")

    async def run(self) -> None:
        while True:
            await asyncio.sleep(INTERVAL)
            try:
                pending = self.drain_dns()
                await asyncio.to_thread(self.store_dns, pending)
                events = await asyncio.to_thread(self.tick)
                if events:
                    self.emit(events)
            except Exception:  # noqa: BLE001 - el bucle no debe morir
                log.exception("Error en el monitor")

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.ensure_future(self.run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

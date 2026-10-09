"""API del historial: tráfico, DNS y registro de conexiones.

Sin `from __future__ import annotations`: FastAPI evalúa las dependencias de `deps`.
"""
import datetime as dt
import sqlite3
import time

from fastapi import FastAPI, HTTPException

from .monitor import day_of

RANGES = {"24h": ("hour", 24), "7d": ("day", 7), "30d": ("day", 30), "12m": ("month", 12)}


def bucket_keys(unit: str, n: int, now: float) -> list:
    """Claves de los últimos n periodos, del más antiguo al actual."""
    if unit == "hour":
        h = int(now // 3600)
        return list(range(h - n + 1, h + 1))
    today = dt.date.fromtimestamp(now)
    if unit == "day":
        return [(today - dt.timedelta(days=i)).isoformat() for i in range(n - 1, -1, -1)]
    y, m = today.year, today.month
    out = []
    for _ in range(n):
        out.append(f"{y:04d}-{m:02d}")
        y, m = (y, m - 1) if m > 1 else (y - 1, 12)
    return out[::-1]


def series(c: sqlite3.Connection, table: str, cols: tuple[str, ...], unit: str, keys: list,
           where: str, args: tuple) -> list[dict]:
    """Suma `cols` por periodo. `where` restringe a los clientes/dispositivos visibles."""
    if unit == "hour":
        col, lo = "hour", keys[0]
    else:
        col, lo = "day", (keys[0] if unit == "day" else keys[0] + "-01")
    group = "substr(day, 1, 7)" if unit == "month" else col
    sums = ", ".join(f"SUM({x}) AS {x}" for x in cols)
    rows = c.execute(f"SELECT {group} AS k, {sums} FROM {table} WHERE {col} >= ? AND {where} GROUP BY k",
                     (lo, *args)).fetchall()
    found = {r["k"]: r for r in rows}
    return [{"key": k, **{x: int((found[k][x] if k in found else 0) or 0) for x in cols}} for k in keys]


def register(app: FastAPI, d) -> None:

    def scope(p, c: sqlite3.Connection, tenant_id: int | None, device_id: int | None) -> tuple[str, tuple, dict]:
        """Filtro SQL (tenant_id / device_id) según quién pregunta; {t} = prefijo de tabla."""
        if not p.is_admin:
            tenant_id = p.tenant_id
        info: dict = {"tenant": None, "device": None}
        if tenant_id is not None:
            info["tenant"] = d.tenant_or_404(c, tenant_id)["name"]
        allowed = d.visible_devices(p, c)  # None = todos los del cliente
        if device_id is not None:
            dev = c.execute("SELECT id, tenant_id, name FROM devices WHERE id = ?", (device_id,)).fetchone()
            if (not dev or (tenant_id is not None and dev["tenant_id"] != tenant_id)
                    or (allowed is not None and device_id not in allowed)):
                raise HTTPException(404, "Dispositivo no encontrado")
            info["device"] = dev["name"]
            return "{t}device_id = ?", (device_id,), info
        if allowed is not None:
            ids = sorted(allowed) or [-1]
            return f"{{t}}device_id IN ({','.join('?' * len(ids))})", tuple(ids), info
        if tenant_id is not None:
            return "{t}tenant_id = ?", (tenant_id,), info
        return "1 = 1", (), info

    def range_of(value: str) -> tuple[str, int]:
        if value not in RANGES:
            raise HTTPException(422, "Rango no válido (24h, 7d, 30d o 12m)")
        return RANGES[value]

    @app.get("/api/history/traffic")
    def traffic(p: d.Anyone, c: d.Conn, range: str = "24h", tenant_id: int | None = None, device_id: int | None = None):
        unit, n = range_of(range)
        where, args, info = scope(p, c, tenant_id, device_id)
        now = time.time()
        keys = bucket_keys(unit, n, now)
        table = "traffic_hourly" if unit == "hour" else "traffic_daily"
        buckets = series(c, table, ("rx", "tx"), unit, keys, where.format(t=""), args)
        lo_col, lo = ("hour", keys[0]) if unit == "hour" else ("day", keys[0] if unit == "day" else keys[0] + "-01")
        rows = c.execute(
            f"""SELECT x.device_id, x.tenant_id, SUM(x.rx) AS rx, SUM(x.tx) AS tx, dv.name AS name, t.name AS tenant
                FROM {table} x LEFT JOIN devices dv ON dv.id = x.device_id JOIN tenants t ON t.id = x.tenant_id
                WHERE x.{lo_col} >= ? AND {where.format(t="x.")} GROUP BY x.device_id ORDER BY SUM(x.rx + x.tx) DESC""",
            (lo, *args)).fetchall()
        devices = [{"id": r["device_id"], "name": r["name"] or "Dispositivo eliminado", "tenant_id": r["tenant_id"],
                    "tenant": r["tenant"], "deleted": r["name"] is None, "rx": r["rx"], "tx": r["tx"]} for r in rows]
        tenants: dict[int, dict] = {}
        for x in devices:
            t = tenants.setdefault(x["tenant_id"], {"id": x["tenant_id"], "name": x["tenant"], "rx": 0, "tx": 0})
            t["rx"] += x["rx"]
            t["tx"] += x["tx"]
        return {
            "range": range, "unit": unit, "scope": info, "buckets": buckets,
            "total": {"rx": sum(b["rx"] for b in buckets), "tx": sum(b["tx"] for b in buckets)},
            "devices": devices[:10],
            "tenants": sorted(tenants.values(), key=lambda t: t["rx"] + t["tx"], reverse=True)[:10]
            if p.is_admin and tenant_id is None and device_id is None else [],
        }

    @app.get("/api/history/dns")
    def dns_history(p: d.User, c: d.Conn, range: str = "24h", tenant_id: int | None = None):
        unit, n = range_of(range)
        where, args, info = scope(p, c, tenant_id, None)
        keys = bucket_keys(unit, n, time.time())
        table = "dns_hourly" if unit == "hour" else "dns_daily"
        buckets = series(c, table, ("queries", "blocked"), unit, keys, where.format(t=""), args)
        first_day = day_of(keys[0] * 3600) if unit == "hour" else (keys[0] if unit == "day" else keys[0] + "-01")
        top = c.execute(f"""SELECT domain, SUM(count) AS count FROM dns_top WHERE day >= ? AND {where.format(t="")}
                            GROUP BY domain ORDER BY SUM(count) DESC LIMIT 15""", (first_day, *args)).fetchall()
        total = {"queries": sum(b["queries"] for b in buckets), "blocked": sum(b["blocked"] for b in buckets)}
        return {"range": range, "unit": unit, "scope": info, "buckets": buckets, "total": total,
                "enabled": d.settings.dns_enabled, "top": [dict(r) for r in top]}

    @app.get("/api/history/events")
    def events(p: d.Anyone, c: d.Conn, tenant_id: int | None = None, device_id: int | None = None,
               limit: int = 50, before: int | None = None):
        where, args, _ = scope(p, c, tenant_id, device_id)
        limit = max(1, min(limit, 200))
        cond = where.format(t="e.") + (" AND e.ts < ?" if before else "")
        rows = c.execute(
            f"""SELECT e.id, e.ts, e.kind, e.device_id, e.endpoint, e.tenant_id, dv.name AS device, dv.kind AS device_kind,
                       t.name AS tenant
                FROM conn_events e LEFT JOIN devices dv ON dv.id = e.device_id JOIN tenants t ON t.id = e.tenant_id
                WHERE {cond} ORDER BY e.ts DESC, e.id DESC LIMIT ?""",
            (*args, *((before,) if before else ()), limit + 1)).fetchall()
        items = [{"id": r["id"], "ts": r["ts"], "kind": r["kind"], "device_id": r["device_id"],
                  "device": r["device"] or "Dispositivo eliminado", "device_kind": r["device_kind"],
                  "endpoint": r["endpoint"], "tenant_id": r["tenant_id"], "tenant": r["tenant"]} for r in rows[:limit]]
        return {"events": items, "more": len(rows) > limit}

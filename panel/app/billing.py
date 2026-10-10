"""Cobros con Stripe: planes, suscripciones, impagos y alta de clientes.

* El admin conecta su cuenta de Stripe pegando la clave secreta: el panel crea
  el webhook y los productos/precios de cada plan automáticamente.
* Cada plan fija los límites del cliente (dispositivos, puertos, servicios,
  usuarios y salidas por país). Al cambiar de plan se aplican al momento.
* El cliente se suscribe o cambia de plan desde el panel (Stripe Checkout) y
  gestiona su tarjeta y facturas en el portal de Stripe.
* Impago: periodo de gracia configurable y después suspensión automática; al
  pagar se reactiva solo. Una suspensión manual del admin nunca se levanta sola.
* Registro público opcional: un cliente nuevo elige plan, paga y su red se
  crea al confirmarse el pago.

Cliente de la API de Stripe con urllib (sin dependencias) y verificación de
firma de los webhooks (HMAC-SHA256, tolerancia de 5 minutos).

Sin `from __future__ import annotations`: FastAPI evalúa las dependencias de `deps`.
"""
import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

from . import security
from . import cfdns
from .db import get_setting, set_setting, username_taken

log = logging.getLogger("wgp.billing")

API_VERSION = "2024-06-20"
WEBHOOK_EVENTS = [
    "checkout.session.completed",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "invoice.payment_failed",
    "invoice.paid",
]
OK_STATUSES = {"active", "trialing"}
DUE_STATUSES = {"past_due", "unpaid", "incomplete"}
PENDING_TTL = 48 * 3600
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


class StripeError(Exception):
    pass


def _flatten(params: dict, prefix: str = "") -> list[tuple[str, str]]:
    """{'a': {'b': [1, 2]}} -> a[b][0]=1&a[b][1]=2 (formato de la API de Stripe)."""
    out: list[tuple[str, str]] = []
    for k, v in params.items():
        key = f"{prefix}[{k}]" if prefix else str(k)
        if v is None:
            continue
        if isinstance(v, dict):
            out += _flatten(v, key)
        elif isinstance(v, (list, tuple)):
            for i, x in enumerate(v):
                out += _flatten({str(i): x}, key)
        elif isinstance(v, bool):
            out.append((key, "true" if v else "false"))
        else:
            out.append((key, str(v)))
    return out


class Stripe:
    def __init__(self, secret_key: str, base: str | None = None) -> None:
        self.key = secret_key
        self.base = (base or os.environ.get("STRIPE_API") or "https://api.stripe.com").rstrip("/")

    @property
    def live(self) -> bool:
        return "_live_" in self.key

    def request(self, method: str, path: str, params: dict | None = None) -> dict:
        data = urllib.parse.urlencode(_flatten(params or {})).encode()
        url = f"{self.base}/v1/{path.lstrip('/')}"
        if method == "GET" and data:
            url, data = f"{url}?{data.decode()}", None
        elif method == "DELETE":
            data = None
        req = urllib.request.Request(url, data=data if method == "POST" else None, method=method, headers={
            "Authorization": f"Bearer {self.key}", "Stripe-Version": API_VERSION,
            "Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=30) as res:
                return json.loads(res.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                err = json.loads(exc.read()).get("error", {})
                msg = err.get("message") or err.get("code") or f"HTTP {exc.code}"
            except ValueError:
                msg = f"HTTP {exc.code}"
            raise StripeError(f"Stripe: {msg}") from None
        except (OSError, ValueError) as exc:
            raise StripeError(f"No se pudo conectar con Stripe: {exc}") from None


def verify_signature(payload: bytes, header: str, secret: str, tolerance: int = 300, now: float | None = None) -> bool:
    try:
        parts = dict(p.split("=", 1) for p in header.split(",") if "=" in p)
        sigs = [p.split("=", 1)[1] for p in header.split(",") if p.startswith("v1=")]
        ts = int(parts["t"])
    except (KeyError, ValueError):
        return False
    if abs((time.time() if now is None else now) - ts) > tolerance:
        return False
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, s) for s in sigs)


def sign(payload: bytes, secret: str, ts: int | None = None) -> str:
    """Cabecera Stripe-Signature (para pruebas)."""
    ts = int(time.time()) if ts is None else ts
    return f"t={ts},v1={hmac.new(secret.encode(), f'{ts}.'.encode() + payload, hashlib.sha256).hexdigest()}"


def fmt_money(cents: int, currency: str = "eur") -> str:
    value = f"{cents / 100:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return f"{value} €" if currency == "eur" else f"{value} {currency.upper()}"


# --------------------------------------------------------------------------- modelos
class StripeIn(BaseModel):
    secret_key: str = Field(min_length=20, max_length=200)


class BillingSettingsIn(BaseModel):
    grace_days: int | None = Field(default=None, ge=0, le=60)
    signup: bool | None = None
    tax: bool | None = None


class PlanIn(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    description: str = Field(default="", max_length=200)
    price_cents: int = Field(ge=0, le=10_000_000)
    interval: str = Field(default="month", pattern="^(month|year)$")
    trial_days: int = Field(default=0, ge=0, le=90)
    max_devices: int = Field(default=10, ge=1, le=16384)
    max_forwards: int = Field(default=0, ge=0, le=100)
    max_services: int = Field(default=0, ge=0, le=100)
    max_members: int = Field(default=0, ge=0, le=500)
    allow_exits: bool = False
    public: bool = True


class PlanUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=40)
    description: str | None = Field(default=None, max_length=200)
    price_cents: int | None = Field(default=None, ge=0, le=10_000_000)
    interval: str | None = Field(default=None, pattern="^(month|year)$")
    trial_days: int | None = Field(default=None, ge=0, le=90)
    max_devices: int | None = Field(default=None, ge=1, le=16384)
    max_forwards: int | None = Field(default=None, ge=0, le=100)
    max_services: int | None = Field(default=None, ge=0, le=100)
    max_members: int | None = Field(default=None, ge=0, le=500)
    allow_exits: bool | None = None
    public: bool | None = None
    active: bool | None = None
    sort: int | None = Field(default=None, ge=0, le=1000)


class AssignIn(BaseModel):
    plan_id: int | None = None        # None = sin plan (límites manuales)
    free: bool = False                # cliente gratuito (proyectos propios): nunca se cobra ni se suspende


class CheckoutIn(BaseModel):
    plan_id: int


class SignupIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    email: str = Field(min_length=5, max_length=254)
    username: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$")
    password: str = Field(min_length=8, max_length=256)
    plan_id: int


# --------------------------------------------------------------------------- motor
class Billing:
    def __init__(self, settings, database, apply_wg=None, notify=None) -> None:
        self.settings = settings
        self.db = database
        self.apply_wg = apply_wg or (lambda: None)
        self.notify = notify          # callback(role, user_id, title, body, url, email)
        self._task: asyncio.Task | None = None

    # ---- Stripe
    def client(self, c: sqlite3.Connection) -> Stripe | None:
        key = get_setting(c, "stripe_secret_key")
        return Stripe(key) if key else None

    def require(self, c: sqlite3.Connection) -> Stripe:
        s = self.client(c)
        if s is None:
            raise HTTPException(409, "Los pagos no están activados (conecta Stripe en Facturación)")
        return s

    def sync_plan(self, c: sqlite3.Connection, plan: sqlite3.Row, s: Stripe | None = None) -> None:
        """Crea en Stripe el producto y el precio del plan si faltan (o si cambió el precio)."""
        s = s or self.client(c)
        if s is None or plan["price_cents"] <= 0:
            return
        product = plan["stripe_product_id"]
        if not product:
            product = s.request("POST", "products", {"name": plan["name"], "metadata": {"wgp_plan": plan["id"]}})["id"]
            c.execute("UPDATE plans SET stripe_product_id = ? WHERE id = ?", (product, plan["id"]))
        else:
            s.request("POST", f"products/{product}", {"name": plan["name"], "active": True})
        if not plan["stripe_price_id"]:
            price = s.request("POST", "prices", {
                "product": product, "currency": plan["currency"], "unit_amount": plan["price_cents"],
                "recurring": {"interval": plan["interval"]}, "metadata": {"wgp_plan": plan["id"]}})["id"]
            c.execute("UPDATE plans SET stripe_price_id = ? WHERE id = ?", (price, plan["id"]))

    def cancel_subscription(self, c: sqlite3.Connection, t: sqlite3.Row) -> None:
        """Al borrar un cliente: se cancela su suscripción para que no se le siga cobrando."""
        if not t["stripe_subscription_id"] or t["billing_status"] in ("canceled", "none", "manual", "pending"):
            return
        s = self.client(c)
        if s is None:
            raise HTTPException(409, "El cliente tiene una suscripción en Stripe: conecta Stripe para cancelarla antes de borrarlo")
        try:
            s.request("DELETE", f"subscriptions/{t['stripe_subscription_id']}")
        except StripeError as exc:
            raise HTTPException(409, f"No se pudo cancelar su suscripción: {exc}") from None

    # ---- planes y límites
    def apply_plan(self, c: sqlite3.Connection, tenant_id: int, plan_id: int | None) -> None:
        c.execute("UPDATE tenants SET plan_id = ? WHERE id = ?", (plan_id, tenant_id))
        if plan_id is None:
            return
        p = c.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
        if p is None:
            return
        c.execute("""UPDATE tenants SET max_devices = ?, max_forwards = ?, max_services = ?, max_members = ?, allow_exits = ?
                     WHERE id = ?""",
                  (p["max_devices"], p["max_forwards"], p["max_services"], p["max_members"], p["allow_exits"], tenant_id))

    def plan_for_price(self, c: sqlite3.Connection, price_id: str | None) -> int | None:
        if not price_id:
            return None
        row = c.execute("SELECT id FROM plans WHERE stripe_price_id = ?", (price_id,)).fetchone()
        if row:
            return row["id"]
        row = c.execute("SELECT plan_id FROM plan_prices WHERE price_id = ?", (price_id,)).fetchone()
        return row["plan_id"] if row else None

    # ---- estado de la suscripción
    def apply_subscription(self, c: sqlite3.Connection, sub: dict) -> int | None:
        """Actualiza el cliente con el estado de una suscripción de Stripe. Devuelve su id."""
        tenant_id = None
        meta = sub.get("metadata") or {}
        if str(meta.get("wgp_tenant", "")).isdigit():
            tenant_id = int(meta["wgp_tenant"])
        row = None
        if tenant_id:
            row = c.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
        if row is None:
            row = c.execute("SELECT * FROM tenants WHERE stripe_subscription_id = ? OR stripe_customer_id = ?",
                            (sub.get("id"), sub.get("customer"))).fetchone()
        if row is None:
            log.warning("Suscripción %s sin cliente asociado", sub.get("id"))
            return None
        items = ((sub.get("items") or {}).get("data") or [])
        price = items[0]["price"]["id"] if items and items[0].get("price") else None
        status = sub.get("status", "")
        period_end = sub.get("current_period_end") or (items[0].get("current_period_end") if items else None)
        c.execute("""UPDATE tenants SET stripe_subscription_id = ?, stripe_customer_id = COALESCE(stripe_customer_id, ?),
                     billing_status = ?, current_period_end = ?, cancel_at_period_end = ? WHERE id = ?""",
                  (sub.get("id"), sub.get("customer"), status, period_end, int(bool(sub.get("cancel_at_period_end"))),
                   row["id"]))
        plan_id = self.plan_for_price(c, price)
        # Lo que paga realmente (puede ser un precio antiguo del plan): para los ingresos mensuales.
        unit = items[0]["price"].get("unit_amount") if items and items[0].get("price") else None
        interval = ((items[0]["price"].get("recurring") or {}).get("interval")) if items and items[0].get("price") else None
        if unit is not None:
            c.execute("UPDATE tenants SET subscription_cents = ?, subscription_interval = ? WHERE id = ?",
                      (int(unit), interval or "month", row["id"]))
        if plan_id and status in OK_STATUSES | DUE_STATUSES:
            self.apply_plan(c, row["id"], plan_id)
        self.enforce(c, row["id"])
        return row["id"]

    def enforce(self, c: sqlite3.Connection, tenant_id: int, now: float | None = None) -> str | None:
        """Suspende o reactiva según el estado del pago. Devuelve 'suspended'/'resumed'/None."""
        now = time.time() if now is None else now
        t = c.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
        status = t["billing_status"] or "none"
        if status in ("none", "manual", "free"):
            return None
        grace = int(get_setting(c, "billing_grace_days") or 7) * 86400
        change = None
        if status in OK_STATUSES:
            c.execute("UPDATE tenants SET past_due_since = NULL WHERE id = ?", (tenant_id,))
            if not t["enabled"] and t["suspended_reason"] == "billing":
                c.execute("UPDATE tenants SET enabled = 1, suspended_reason = '' WHERE id = ?", (tenant_id,))
                change = "resumed"
        elif status in DUE_STATUSES:
            since = t["past_due_since"] or int(now)
            if not t["past_due_since"]:
                c.execute("UPDATE tenants SET past_due_since = ? WHERE id = ?", (since, tenant_id))
            if now - since >= grace and t["enabled"]:
                c.execute("UPDATE tenants SET enabled = 0, suspended_reason = 'billing' WHERE id = ?", (tenant_id,))
                change = "suspended"
        elif status in ("canceled", "incomplete_expired", "pending") and t["enabled"]:
            c.execute("UPDATE tenants SET enabled = 0, suspended_reason = 'billing' WHERE id = ?", (tenant_id,))
            change = "suspended"
        if change:
            c.commit()
            self.apply_wg()
            self._notify_change(t, change)
        return change

    def _notify_change(self, t: sqlite3.Row, change: str) -> None:
        if not self.notify:
            return
        if change == "suspended":
            self.notify(t, "⛔ Servicio suspendido por falta de pago",
                        "Tu red privada está en pausa. Actualiza tu forma de pago en el panel (Plan) y se reactivará al momento.")
        else:
            self.notify(t, "✅ Pago recibido", "Tu red privada vuelve a estar activa.")

    def check_all(self, now: float | None = None) -> None:
        """Revisión periódica: periodos de gracia vencidos y altas sin pagar."""
        now = time.time() if now is None else now
        with self.db.conn() as c:
            for t in c.execute("SELECT id FROM tenants WHERE billing_status IN ('past_due', 'unpaid', 'incomplete')").fetchall():
                self.enforce(c, t["id"], now)
            for t in c.execute("SELECT id FROM tenants WHERE billing_status = 'pending' AND created_at < ?",
                               (int(now - PENDING_TTL),)).fetchall():
                log.info("Alta sin pagar caducada: cliente %s eliminado", t["id"])
                c.execute("DELETE FROM tenants WHERE id = ?", (t["id"],))
                c.execute("DELETE FROM passkeys WHERE role = 'tenant' AND user_id = ?", (t["id"],))

    async def run(self) -> None:
        while True:
            await asyncio.sleep(600)
            try:
                await asyncio.to_thread(self.check_all)
            except Exception:  # noqa: BLE001 - el bucle no debe morir
                log.exception("Error revisando la facturación")

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.ensure_future(self.run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()


# --------------------------------------------------------------------------- API
def register(app: FastAPI, d) -> None:
    b: Billing = d.billing

    def public_base(c: sqlite3.Connection) -> str:
        main = d.doms.main_domain(c)
        if not main:
            raise HTTPException(409, "Configura primero el dominio del panel (Ajustes) con HTTPS: Stripe lo necesita")
        return f"https://{main}"

    def return_base(c: sqlite3.Connection, request: Request | None) -> str:
        """A dónde vuelve el cliente tras pagar: al mismo dominio desde el que vino (la página
        pública sirve el panel en su ruta, /dashboard por defecto) o, si no, al dominio del panel."""
        host = d.host_of(request.headers.get("host")) if request is not None else None
        if host and host in d.doms.site_domains(c, only_enabled=True):
            return f"https://{host}/{get_setting(c, 'site_path') or 'dashboard'}"   # site.panel_path (sin importarlo: ciclo)
        if host and d.doms.tenant_for_host(c, host) is not None:
            return f"https://{host}/"
        return public_base(c) + "/"

    def plan_json(p: sqlite3.Row, admin: bool = False, c: sqlite3.Connection | None = None) -> dict:
        out = {k: p[k] for k in ("id", "name", "description", "price_cents", "currency", "interval", "trial_days",
                                 "max_devices", "max_forwards", "max_services", "max_members")}
        out.update(allow_exits=bool(p["allow_exits"]), price=fmt_money(p["price_cents"], p["currency"]))
        if admin and c is not None:
            subs = c.execute("SELECT COUNT(*) FROM tenants WHERE plan_id = ?", (p["id"],)).fetchone()[0]
            out.update(public=bool(p["public"]), active=bool(p["active"]), sort=p["sort"], tenants=subs,
                       stripe_price_id=p["stripe_price_id"])
        return out

    def plan_or_404(c: sqlite3.Connection, plan_id: int, active_only: bool = False) -> sqlite3.Row:
        row = c.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
        if not row or (active_only and not row["active"]):
            raise HTTPException(404, "Plan no encontrado")
        return row

    # ---------------------------------------------------------------- admin
    @app.get("/api/admin/billing")
    def admin_billing(_: d.Admin, c: d.Conn):
        plans = c.execute("SELECT * FROM plans ORDER BY active DESC, sort, price_cents").fetchall()
        key = get_setting(c, "stripe_secret_key") or ""
        mrr = 0
        counts = {"active": 0, "trialing": 0, "past_due": 0, "suspended": 0, "manual": 0, "free": 0}
        attention = []
        for t in c.execute("""SELECT t.*, COALESCE(t.subscription_cents, p.price_cents) AS paid,
                                     COALESCE(t.subscription_interval, p.interval) AS paid_interval, p.name AS plan_name
                              FROM tenants t LEFT JOIN plans p ON p.id = t.plan_id""").fetchall():
            st = t["billing_status"] or "none"
            if st in ("active", "trialing"):
                counts[st] += 1
                if st == "active" and t["paid"]:
                    mrr += t["paid"] if t["paid_interval"] == "month" else round(t["paid"] / 12)
            elif st in ("manual", "free"):
                counts[st] += 1
            if st in DUE_STATUSES:
                counts["past_due"] += 1
            if t["suspended_reason"] == "billing" and st != "pending":
                counts["suspended"] += 1
            if st in DUE_STATUSES or (t["suspended_reason"] == "billing" and st != "pending"):
                attention.append({"id": t["id"], "name": t["name"], "status": st, "plan": t["plan_name"],
                                  "past_due_since": t["past_due_since"], "suspended": not t["enabled"]})
        return {
            "stripe": {"connected": bool(key), "live": "_live_" in key, "account": get_setting(c, "stripe_account") or "",
                       "webhook": bool(get_setting(c, "stripe_webhook_secret"))},
            "settings": {"grace_days": int(get_setting(c, "billing_grace_days") or 7),
                         "signup": get_setting(c, "billing_signup") == "1", "tax": get_setting(c, "billing_tax") == "1"},
            "plans": [plan_json(p, True, c) for p in plans],
            "stats": {"mrr_cents": mrr, "mrr": fmt_money(mrr), **counts}, "attention": attention,
        }

    @app.put("/api/admin/billing/stripe")
    def connect_stripe(body: StripeIn, _: d.Admin, c: d.Conn):
        key = body.secret_key.strip()
        if not re.fullmatch(r"(sk|rk)_(test|live)_[A-Za-z0-9]{10,}", key):
            raise HTTPException(422, "Clave no válida: usa la clave secreta (sk_live_… o sk_test_…) de Stripe › Desarrolladores › Claves de API")
        base = public_base(c)
        s = Stripe(key)
        try:
            account = s.request("GET", "account")
            old = get_setting(c, "stripe_webhook_id")
            if old and get_setting(c, "stripe_secret_key"):
                try:
                    Stripe(get_setting(c, "stripe_secret_key")).request("DELETE", f"webhook_endpoints/{old}")
                except StripeError:
                    pass
            hook = s.request("POST", "webhook_endpoints", {
                "url": f"{base}/api/billing/webhook", "enabled_events": WEBHOOK_EVENTS, "api_version": API_VERSION,
                "description": "Panel WireGuard Cloud"})
        except StripeError as exc:
            raise HTTPException(409, str(exc)) from None
        name = ((account.get("settings") or {}).get("dashboard") or {}).get("display_name") \
            or (account.get("business_profile") or {}).get("name") or account.get("email") or account.get("id", "")
        set_setting(c, "stripe_secret_key", key)
        set_setting(c, "stripe_account", name)
        set_setting(c, "stripe_webhook_id", hook["id"])
        set_setting(c, "stripe_webhook_secret", hook["secret"])
        # Si cambia la cuenta (p. ej. de pruebas a real), los productos se crean de nuevo.
        c.execute("UPDATE plans SET stripe_product_id = NULL, stripe_price_id = NULL")
        try:
            for p in c.execute("SELECT * FROM plans WHERE active = 1").fetchall():
                b.sync_plan(c, p, s)
        except StripeError as exc:
            raise HTTPException(409, str(exc)) from None
        return admin_billing(_, c)

    @app.delete("/api/admin/billing/stripe")
    def disconnect_stripe(_: d.Admin, c: d.Conn):
        s = b.client(c)
        hook = get_setting(c, "stripe_webhook_id")
        if s and hook:
            try:
                s.request("DELETE", f"webhook_endpoints/{hook}")
            except StripeError:
                pass
        for k in ("stripe_secret_key", "stripe_webhook_id", "stripe_webhook_secret", "stripe_account"):
            set_setting(c, k, "")
        return admin_billing(_, c)

    @app.put("/api/admin/billing/settings")
    def billing_settings(body: BillingSettingsIn, _: d.Admin, c: d.Conn):
        if body.grace_days is not None:
            set_setting(c, "billing_grace_days", str(body.grace_days))
        if body.signup is not None:
            set_setting(c, "billing_signup", "1" if body.signup else "0")
        if body.tax is not None:
            set_setting(c, "billing_tax", "1" if body.tax else "0")
        return admin_billing(_, c)

    @app.post("/api/admin/plans", status_code=201)
    def create_plan(body: PlanIn, _: d.Admin, c: d.Conn):
        cur = c.execute(
            """INSERT INTO plans (name, description, price_cents, currency, interval, trial_days, max_devices, max_forwards,
                                  max_services, max_members, allow_exits, public, created_at)
               VALUES (?, ?, ?, 'eur', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (body.name.strip(), body.description.strip(), body.price_cents, body.interval, body.trial_days, body.max_devices,
             body.max_forwards, body.max_services, body.max_members, int(body.allow_exits), int(body.public), int(time.time())))
        try:
            b.sync_plan(c, plan_or_404(c, cur.lastrowid))
        except StripeError as exc:
            raise HTTPException(409, str(exc)) from None
        return plan_json(plan_or_404(c, cur.lastrowid), True, c)

    @app.patch("/api/admin/plans/{plan_id}")
    def update_plan(plan_id: int, body: PlanUpdate, _: d.Admin, c: d.Conn):
        p = plan_or_404(c, plan_id)
        values = body.model_dump(exclude_none=True)
        price_changed = any(k in values and values[k] != p[k] for k in ("price_cents", "interval"))
        for k, v in values.items():
            c.execute(f"UPDATE plans SET {k} = ? WHERE id = ?", (int(v) if isinstance(v, bool) else v, plan_id))
        s = b.client(c)
        try:
            if price_changed and p["stripe_price_id"]:
                # Los precios de Stripe no se modifican: se crea otro y el anterior se archiva.
                # Los suscriptores actuales mantienen su precio hasta que cambien de plan.
                c.execute("INSERT OR IGNORE INTO plan_prices (price_id, plan_id) VALUES (?, ?)", (p["stripe_price_id"], plan_id))
                if s:
                    s.request("POST", f"prices/{p['stripe_price_id']}", {"active": False})
                c.execute("UPDATE plans SET stripe_price_id = NULL WHERE id = ?", (plan_id,))
            p = plan_or_404(c, plan_id)
            if p["active"]:
                b.sync_plan(c, p, s)
            elif s and p["stripe_product_id"]:
                s.request("POST", f"products/{p['stripe_product_id']}", {"active": False})
        except StripeError as exc:
            raise HTTPException(409, str(exc)) from None
        # Los límites nuevos se aplican a todos los clientes de este plan.
        for t in c.execute("SELECT id FROM tenants WHERE plan_id = ?", (plan_id,)).fetchall():
            b.apply_plan(c, t["id"], plan_id)
        c.commit()
        d.apply_wg()
        return plan_json(plan_or_404(c, plan_id), True, c)

    @app.delete("/api/admin/plans/{plan_id}")
    def delete_plan(plan_id: int, _: d.Admin, c: d.Conn):
        p = plan_or_404(c, plan_id)
        if c.execute("SELECT COUNT(*) FROM tenants WHERE plan_id = ?", (plan_id,)).fetchone()[0]:
            raise HTTPException(409, "Hay clientes con este plan: desactívalo en lugar de borrarlo")
        s = b.client(c)
        if s and p["stripe_product_id"]:
            try:
                if p["stripe_price_id"]:
                    s.request("POST", f"prices/{p['stripe_price_id']}", {"active": False})
                s.request("POST", f"products/{p['stripe_product_id']}", {"active": False})
            except StripeError:
                pass
        c.execute("DELETE FROM plans WHERE id = ?", (plan_id,))
        return {"ok": True}

    @app.put("/api/admin/tenants/{tenant_id}/plan")
    def assign_plan(tenant_id: int, body: AssignIn, _: d.Admin, c: d.Conn):
        """Asignación manual (sin cobro por Stripe): clientes que pagan por transferencia o gratuitos."""
        t = d.tenant_or_404(c, tenant_id)
        if body.plan_id is not None:
            plan_or_404(c, body.plan_id)
        if body.free:
            # Gratuito: si pagaba con Stripe, se cancela la suscripción para no cobrarle más.
            b.cancel_subscription(c, t)
            c.execute("""UPDATE tenants SET billing_status = 'free', past_due_since = NULL, stripe_subscription_id = NULL,
                         cancel_at_period_end = 0, subscription_cents = NULL WHERE id = ?""", (tenant_id,))
            t = d.tenant_or_404(c, tenant_id)
        b.apply_plan(c, tenant_id, body.plan_id)
        if body.free:
            if not t["enabled"] and t["suspended_reason"] == "billing":
                c.execute("UPDATE tenants SET enabled = 1, suspended_reason = '' WHERE id = ?", (tenant_id,))
        elif (not t["stripe_subscription_id"] or t["billing_status"] in ("canceled", "none", "pending", "free")):
            c.execute("UPDATE tenants SET billing_status = ?, past_due_since = NULL WHERE id = ?",
                      ("manual" if body.plan_id else "none", tenant_id))
            if not t["enabled"] and t["suspended_reason"] == "billing":
                c.execute("UPDATE tenants SET enabled = 1, suspended_reason = '' WHERE id = ?", (tenant_id,))
        c.commit()
        d.apply_wg()
        return tenant_billing(c, tenant_id)

    # ---------------------------------------------------------------- cliente
    def tenant_billing(c: sqlite3.Connection, tid: int) -> dict:
        t = d.tenant_or_404(c, tid)
        plan = c.execute("SELECT * FROM plans WHERE id = ?", (t["plan_id"],)).fetchone() if t["plan_id"] else None
        count = lambda table: c.execute(f"SELECT COUNT(*) FROM {table} WHERE tenant_id = ?", (tid,)).fetchone()[0]  # noqa: E731
        grace = int(get_setting(c, "billing_grace_days") or 7)
        return {
            "plan": plan_json(plan) if plan else None, "status": t["billing_status"] or "none",
            "period_end": t["current_period_end"], "cancel_at_period_end": bool(t["cancel_at_period_end"]),
            "past_due_since": t["past_due_since"],
            "suspend_at": t["past_due_since"] + grace * 86400 if t["past_due_since"] else None,
            "suspended": not t["enabled"] and t["suspended_reason"] == "billing",
            "has_customer": bool(t["stripe_customer_id"]), "stripe": bool(get_setting(c, "stripe_secret_key")),
            "limits": {"devices": t["max_devices"], "forwards": t["max_forwards"], "services": t["max_services"],
                       "members": t["max_members"], "exits": bool(t["allow_exits"])},
            "usage": {"devices": count("devices"), "forwards": count("forwards"), "services": count("services"),
                      "members": count("members")},
            "plans": [] if t["billing_status"] == "free" else [plan_json(p) for p in c.execute(
                "SELECT * FROM plans WHERE active = 1 AND public = 1 AND price_cents > 0 ORDER BY sort, price_cents")],
            "customer_url": f"https://dashboard.stripe.com/{'' if '_live_' in (get_setting(c, 'stripe_secret_key') or '') else 'test/'}customers/{t['stripe_customer_id']}"
            if t["stripe_customer_id"] else None,
        }

    @app.get("/api/billing")
    def get_billing(p: d.BillingUser, c: d.Conn, tenant_id: int | None = None):
        return tenant_billing(c, d.scope_tenant(p, tenant_id))

    def ensure_customer(c: sqlite3.Connection, s: Stripe, t: sqlite3.Row, email: str | None = None) -> str:
        if t["stripe_customer_id"]:
            return t["stripe_customer_id"]
        cus = s.request("POST", "customers", {"name": t["name"], "email": email or t["billing_email"] or None,
                                              "metadata": {"wgp_tenant": t["id"]}})
        c.execute("UPDATE tenants SET stripe_customer_id = ? WHERE id = ?", (cus["id"], t["id"]))
        return cus["id"]

    def checkout_session(c: sqlite3.Connection, s: Stripe, t: sqlite3.Row, plan: sqlite3.Row, base: str,
                         success: str, cancel: str) -> str:
        if not plan["stripe_price_id"]:
            b.sync_plan(c, plan, s)
            plan = plan_or_404(c, plan["id"])
        customer = ensure_customer(c, s, t)
        params = {
            "mode": "subscription", "customer": customer, "client_reference_id": str(t["id"]),
            "line_items": [{"price": plan["stripe_price_id"], "quantity": 1}],
            "subscription_data": {"metadata": {"wgp_tenant": t["id"]},
                                  **({"trial_period_days": plan["trial_days"]} if plan["trial_days"] else {})},
            "success_url": f"{base}{success}", "cancel_url": f"{base}{cancel}",
            "allow_promotion_codes": True, "locale": "es",
        }
        if get_setting(c, "billing_tax") == "1":
            params.update(automatic_tax={"enabled": True}, customer_update={"address": "auto", "name": "auto"},
                          tax_id_collection={"enabled": True}, billing_address_collection="required")
        return s.request("POST", "checkout/sessions", params)["url"]

    @app.post("/api/billing/checkout")
    def checkout(body: CheckoutIn, request: Request, p: d.BillingUser, c: d.Conn, tenant_id: int | None = None):
        tid = d.scope_tenant(p, tenant_id)
        t = d.tenant_or_404(c, tid)
        if t["billing_status"] == "free":
            raise HTTPException(409, "Esta cuenta es gratuita: no necesita contratar un plan")
        plan = plan_or_404(c, body.plan_id, active_only=True)
        if plan["price_cents"] <= 0 or (not plan["public"] and not p.is_admin):
            raise HTTPException(422, "Ese plan no se puede contratar desde aquí")
        s = b.require(c)
        base = return_base(c, request)
        try:
            if t["stripe_subscription_id"] and t["billing_status"] in OK_STATUSES | DUE_STATUSES:
                # Cambio de plan: se prorratea en la siguiente factura.
                if not plan["stripe_price_id"]:
                    b.sync_plan(c, plan, s)
                    plan = plan_or_404(c, plan["id"])
                sub = s.request("GET", f"subscriptions/{t['stripe_subscription_id']}")
                item = sub["items"]["data"][0]["id"]
                sub = s.request("POST", f"subscriptions/{sub['id']}", {
                    "items": [{"id": item, "price": plan["stripe_price_id"]}], "proration_behavior": "create_prorations",
                    "cancel_at_period_end": False, "metadata": {"wgp_tenant": tid}})
                b.apply_subscription(c, sub)
                c.commit()
                d.apply_wg()
                return {"changed": True, **tenant_billing(c, tid)}
            url = checkout_session(c, s, t, plan, base, "#/plan?pago=ok", "#/plan")
        except StripeError as exc:
            raise HTTPException(409, str(exc)) from None
        return {"url": url}

    @app.post("/api/billing/portal")
    def portal(request: Request, p: d.BillingUser, c: d.Conn, tenant_id: int | None = None):
        tid = d.scope_tenant(p, tenant_id)
        t = d.tenant_or_404(c, tid)
        if not t["stripe_customer_id"]:
            raise HTTPException(409, "Aún no tienes datos de pago")
        try:
            url = b.require(c).request("POST", "billing_portal/sessions", {
                "customer": t["stripe_customer_id"], "return_url": f"{return_base(c, request)}#/plan", "locale": "es"})["url"]
        except StripeError as exc:
            raise HTTPException(409, str(exc)) from None
        return {"url": url}

    @app.get("/api/billing/invoices")
    def invoices(p: d.BillingUser, c: d.Conn, tenant_id: int | None = None):
        t = d.tenant_or_404(c, d.scope_tenant(p, tenant_id))
        if not t["stripe_customer_id"] or not b.client(c):
            return {"invoices": []}
        try:
            data = b.require(c).request("GET", "invoices", {"customer": t["stripe_customer_id"], "limit": 24})["data"]
        except StripeError as exc:
            raise HTTPException(409, str(exc)) from None
        return {"invoices": [{"id": i["id"], "number": i.get("number"), "created": i.get("created"),
                              "total": fmt_money(i.get("total", 0), i.get("currency", "eur")), "status": i.get("status"),
                              "url": i.get("hosted_invoice_url"), "pdf": i.get("invoice_pdf")} for i in data]}

    # ---------------------------------------------------------------- alta pública
    @app.get("/api/signup")
    def signup_info(c: d.Conn):
        enabled = get_setting(c, "billing_signup") == "1" and bool(get_setting(c, "stripe_secret_key"))
        plans = c.execute("SELECT * FROM plans WHERE active = 1 AND public = 1 AND price_cents > 0 ORDER BY sort, price_cents")
        return {"enabled": enabled, "plans": [plan_json(p) for p in plans] if enabled else []}

    @app.post("/api/signup")
    def signup(body: SignupIn, request: Request, c: d.Conn):
        key = request.client.host if request.client else "unknown"
        if d.limiter.blocked(key):
            raise HTTPException(429, "Demasiados intentos. Espere unos minutos.")
        d.limiter.hit(key)  # también limita el número de altas por IP
        if not signup_info(c)["enabled"]:
            raise HTTPException(403, "El registro no está abierto")
        plan = plan_or_404(c, body.plan_id, active_only=True)
        if not plan["public"] or plan["price_cents"] <= 0:
            raise HTTPException(422, "Plan no disponible")
        email = body.email.strip()
        if not EMAIL_RE.match(email):
            raise HTTPException(422, "Email no válido")
        if username_taken(c, body.username):
            raise HTTPException(409, "Ese nombre de usuario ya existe; elige otro")
        idx = d.next_net(c)
        if idx is None:
            raise HTTPException(409, "No quedan plazas libres. Contacta con nosotros.")
        name = re.sub(r"\s+", " ", body.name).strip()
        cur = c.execute(
            """INSERT INTO tenants (name, username, password_hash, must_change, net_index, max_devices, notes, created_at,
                                    enabled, suspended_reason, billing_status, billing_email)
               VALUES (?, ?, ?, 0, ?, 1, 'Alta desde la web', ?, 0, 'billing', 'pending', ?)""",
            (name, body.username, security.hash_password(body.password), idx, int(time.time()), email))
        tid = cur.lastrowid
        cfdns.assign(c)
        b.apply_plan(c, tid, plan["id"])
        t = d.tenant_or_404(c, tid)
        try:
            url = checkout_session(c, b.require(c), t, plan, return_base(c, request), "#/signup/ok", "#/signup")
        except StripeError as exc:
            c.rollback()
            raise HTTPException(409, str(exc)) from None
        c.commit()
        return {"url": url}

    # ---------------------------------------------------------------- webhook
    @app.post("/api/billing/webhook")
    async def webhook(request: Request):
        payload = await request.body()
        with d.db.conn() as c:
            secret = get_setting(c, "stripe_webhook_secret")
            if not secret or not verify_signature(payload, request.headers.get("stripe-signature", ""), secret):
                return Response(status_code=400)
            try:
                event = json.loads(payload)
            except ValueError:
                return Response(status_code=400)
            if c.execute("SELECT 1 FROM stripe_events WHERE id = ?", (event.get("id"),)).fetchone():
                return {"ok": True, "duplicate": True}
            c.execute("INSERT INTO stripe_events (id, type, created_at) VALUES (?, ?, ?)",
                      (event.get("id"), event.get("type"), int(time.time())))
            c.execute("DELETE FROM stripe_events WHERE created_at < ?", (int(time.time()) - 30 * 86400,))
            try:
                await asyncio.to_thread(handle_event, c, event)
            except StripeError as exc:
                c.rollback()
                log.error("Webhook %s: %s", event.get("type"), exc)
                return Response(status_code=500)  # Stripe lo reintentará
        return {"ok": True}

    def handle_event(c: sqlite3.Connection, event: dict) -> None:
        kind = event.get("type", "")
        obj = (event.get("data") or {}).get("object") or {}
        if kind == "checkout.session.completed" and obj.get("mode") == "subscription":
            ref = obj.get("client_reference_id")
            if ref and str(ref).isdigit():
                c.execute("UPDATE tenants SET stripe_customer_id = COALESCE(stripe_customer_id, ?), stripe_subscription_id = ? "
                          "WHERE id = ?", (obj.get("customer"), obj.get("subscription"), int(ref)))
                email = ((obj.get("customer_details") or {}).get("email"))
                if email:
                    c.execute("UPDATE tenants SET billing_email = COALESCE(billing_email, ?) WHERE id = ?", (email, int(ref)))
            if obj.get("subscription"):
                s = b.client(c)
                if s:
                    b.apply_subscription(c, s.request("GET", f"subscriptions/{obj['subscription']}"))
        elif kind.startswith("customer.subscription."):
            tid = b.apply_subscription(c, obj)
            if tid and kind == "customer.subscription.created" and d.notify_admins:
                t = d.tenant_or_404(c, tid)
                d.notify_admins("💶 Nueva suscripción", f"{t['name']} se ha suscrito.")
            if tid and kind == "customer.subscription.deleted" and d.notify_admins:
                t = d.tenant_or_404(c, tid)
                d.notify_admins("Suscripción cancelada", f"{t['name']} ha cancelado su suscripción.")
        elif kind == "invoice.payment_failed":
            t = c.execute("SELECT * FROM tenants WHERE stripe_customer_id = ?", (obj.get("customer"),)).fetchone()
            if t and b.notify:
                b.notify(t, "⚠️ No se pudo cobrar tu suscripción",
                         f"Revisa tu tarjeta en el panel (Plan › Gestionar pago). Importe: "
                         f"{fmt_money(obj.get('amount_due', 0), obj.get('currency', 'eur'))}.")
            if t and d.notify_admins:
                d.notify_admins("⚠️ Pago fallido", f"No se pudo cobrar a {t['name']}.")
        elif kind == "invoice.paid":
            sub_id = obj.get("subscription") or ((obj.get("parent") or {}).get("subscription_details") or {}).get("subscription")
            s = b.client(c)
            if sub_id and s:
                b.apply_subscription(c, s.request("GET", f"subscriptions/{sub_id}"))

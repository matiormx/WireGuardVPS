"""Códigos de descuento (Facturación › Códigos de descuento).

Cada código es un cupón de Stripe más su «código promocional» (lo que escribe el
cliente). El descuento es un porcentaje o un importe fijo y dura:

  * once       sólo el primer pago
  * repeating  durante N meses (en un plan anual, cubre las facturas de esos meses)
  * forever    permanente, mientras dure la suscripción

Opcionalmente: límite de usos, fecha de caducidad del código y planes a los que
se aplica. Stripe aplica el descuento en cada factura; el panel lo valida antes
de enviar al cliente a pagar y muestra el precio final.

Los cupones de Stripe no se pueden modificar: un código sólo se activa,
desactiva o borra. Borrarlo no quita el descuento a quien ya lo usa.

Sin `from __future__ import annotations`: FastAPI evalúa las dependencias de `deps`.
"""
import re
import sqlite3
import time
from typing import List, Optional

from fastapi import HTTPException, Request
from pydantic import BaseModel, Field

CODE_RE = re.compile(r"^[A-Z0-9][A-Z0-9_-]{2,31}$")
DURATIONS = ("once", "repeating", "forever")


def clean_code(code: str) -> str:
    return (code or "").strip().upper()


def money(cents: int, currency: str = "eur") -> str:
    value = f"{cents / 100:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return f"{value} €" if currency.lower() == "eur" else f"{value} {currency.upper()}"


def label(r) -> str:
    """«−20 % durante 3 meses», «−5,00 € en el primer pago», «−10 % para siempre»."""
    off = f"−{r['percent_off']:g} %" if r["percent_off"] else f"−{money(r['amount_off'], r['currency'])}"
    when = {"once": "en el primer pago", "forever": "para siempre",
            "repeating": f"durante {r['months']} {'mes' if r['months'] == 1 else 'meses'}"}[r["duration"]]
    return f"{off} {when}"


def discounted(r, price_cents: int) -> int:
    if r["percent_off"]:
        return max(0, round(price_cents * (100 - r["percent_off"]) / 100))
    return max(0, price_cents - (r["amount_off"] or 0))


def plan_ids(r) -> List[int]:
    return [int(x) for x in (r["plan_ids"] or "").split(",") if x.strip()]


def resolve(c: sqlite3.Connection, code: Optional[str], plan, check_plan: bool = True) -> Optional[sqlite3.Row]:
    """El código válido para ese plan, o None si no se ha escrito ninguno. Si no vale, error claro."""
    code = clean_code(code)
    if not code:
        return None
    r = c.execute("SELECT * FROM discounts WHERE code = ? COLLATE NOCASE", (code,)).fetchone()
    if r is None or not r["active"] or not r["stripe_promo_id"]:
        raise HTTPException(422, "Ese código de descuento no existe o ya no está activo")
    if r["expires_at"] and r["expires_at"] < time.time():
        raise HTTPException(422, "Ese código de descuento ha caducado")
    if not check_plan:
        return r
    if plan_ids(r) and plan["id"] not in plan_ids(r):
        raise HTTPException(422, "Ese código no es válido para este plan")
    if r["amount_off"] and r["currency"].lower() != plan["currency"].lower():
        raise HTTPException(422, "Ese código no es válido para este plan")
    return r


class DiscountIn(BaseModel):
    code: str = Field(min_length=3, max_length=32)
    percent_off: Optional[float] = Field(default=None, gt=0, le=100)
    amount_off: Optional[int] = Field(default=None, gt=0, le=1_000_000)     # céntimos
    currency: str = Field(default="eur", pattern=r"^[a-zA-Z]{3}$")
    duration: str = Field(pattern=r"^(once|repeating|forever)$")
    months: Optional[int] = Field(default=None, ge=1, le=60)
    max_redemptions: Optional[int] = Field(default=None, ge=1, le=1_000_000)
    expires_at: Optional[int] = None
    plan_ids: List[int] = Field(default_factory=list)
    note: str = Field(default="", max_length=200)


class DiscountPatch(BaseModel):
    active: Optional[bool] = None
    note: Optional[str] = Field(default=None, max_length=200)


class CheckIn(BaseModel):
    code: str = Field(min_length=1, max_length=40)
    plan_id: Optional[int] = None   # sin plan: sólo se comprueba el código (la página de planes)


def register(app, d) -> None:
    from .billing import StripeError   # aquí: billing importa este módulo

    def json_row(r, redeemed: Optional[int] = None) -> dict:
        return {"id": r["id"], "code": r["code"], "label": label(r), "percent_off": r["percent_off"], "amount_off": r["amount_off"],
                "currency": r["currency"], "duration": r["duration"], "months": r["months"], "max_redemptions": r["max_redemptions"],
                "expires_at": r["expires_at"], "plan_ids": plan_ids(r), "active": bool(r["active"]), "note": r["note"],
                "created_at": r["created_at"], "redeemed": redeemed,
                "expired": bool(r["expires_at"] and r["expires_at"] < time.time())}

    def plan_row(c: sqlite3.Connection, pid: int):
        p = c.execute("SELECT * FROM plans WHERE id = ?", (pid,)).fetchone()
        if p is None:
            raise HTTPException(404, "Plan no encontrado")
        return p

    @app.get("/api/admin/discounts")
    def list_discounts(_: d.Admin, c: d.Conn):
        rows = c.execute("SELECT * FROM discounts ORDER BY created_at DESC, id DESC").fetchall()
        used = {}
        s = d.billing.client(c)
        if s is not None and rows:
            try:
                for pc in s.request("GET", "promotion_codes", {"limit": 100}).get("data", []):
                    used[pc["id"]] = pc.get("times_redeemed", 0)
            except StripeError:
                pass   # sin conexión con Stripe: la lista se muestra igual, sin usos
        return {"discounts": [json_row(r, used.get(r["stripe_promo_id"])) for r in rows]}

    @app.post("/api/admin/discounts", status_code=201)
    def create_discount(body: DiscountIn, _: d.Admin, c: d.Conn):
        code = clean_code(body.code)
        if not CODE_RE.match(code):
            raise HTTPException(422, "Código no válido: letras, números, guiones (3 a 32), p. ej. VERANO20")
        if c.execute("SELECT 1 FROM discounts WHERE code = ? COLLATE NOCASE", (code,)).fetchone():
            raise HTTPException(409, "Ya existe un código con ese nombre")
        if bool(body.percent_off) == bool(body.amount_off):
            raise HTTPException(422, "Indica un porcentaje o un importe, no los dos")
        if body.duration == "repeating" and not body.months:
            raise HTTPException(422, "Indica durante cuántos meses")
        if body.expires_at is not None and body.expires_at <= time.time():
            raise HTTPException(422, "La fecha de caducidad ya ha pasado")
        plans = [plan_row(c, pid) for pid in dict.fromkeys(body.plan_ids)]
        s = d.billing.require(c)
        try:
            products = []
            for p in plans:
                if not p["stripe_product_id"]:
                    d.billing.sync_plan(c, p, s)
                    p = plan_row(c, p["id"])
                if p["stripe_product_id"]:
                    products.append(p["stripe_product_id"])
            coupon = {"duration": body.duration, "name": code[:40], "metadata": {"wgp_code": code}}
            if body.percent_off:
                coupon["percent_off"] = body.percent_off
            else:
                coupon.update(amount_off=body.amount_off, currency=body.currency.lower())
            if body.duration == "repeating":
                coupon["duration_in_months"] = body.months
            if products:
                coupon["applies_to"] = {"products": products}
            coupon_id = s.request("POST", "coupons", coupon)["id"]
            promo = {"coupon": coupon_id, "code": code, "metadata": {"wgp_code": code}}
            if body.max_redemptions:
                promo["max_redemptions"] = body.max_redemptions
            if body.expires_at:
                promo["expires_at"] = body.expires_at
            promo_id = s.request("POST", "promotion_codes", promo)["id"]
        except StripeError as exc:
            raise HTTPException(409, f"Stripe: {exc}") from None
        cur = c.execute(
            """INSERT INTO discounts (code, percent_off, amount_off, currency, duration, months, max_redemptions, expires_at,
                                      plan_ids, active, stripe_coupon_id, stripe_promo_id, note, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)""",
            (code, body.percent_off, body.amount_off, body.currency.lower(), body.duration,
             body.months if body.duration == "repeating" else None, body.max_redemptions, body.expires_at,
             ",".join(str(p["id"]) for p in plans), coupon_id, promo_id, body.note.strip(), int(time.time())))
        return json_row(c.execute("SELECT * FROM discounts WHERE id = ?", (cur.lastrowid,)).fetchone(), 0)

    def discount_or_404(c: sqlite3.Connection, did: int):
        r = c.execute("SELECT * FROM discounts WHERE id = ?", (did,)).fetchone()
        if r is None:
            raise HTTPException(404, "Código no encontrado")
        return r

    @app.patch("/api/admin/discounts/{did}")
    def patch_discount(did: int, body: DiscountPatch, _: d.Admin, c: d.Conn):
        r = discount_or_404(c, did)
        if body.active is not None and bool(body.active) != bool(r["active"]):
            try:
                d.billing.require(c).request("POST", f"promotion_codes/{r['stripe_promo_id']}", {"active": body.active})
            except StripeError as exc:
                raise HTTPException(409, f"Stripe: {exc}") from None
            c.execute("UPDATE discounts SET active = ? WHERE id = ?", (int(body.active), did))
        if body.note is not None:
            c.execute("UPDATE discounts SET note = ? WHERE id = ?", (body.note.strip(), did))
        return json_row(discount_or_404(c, did))

    @app.delete("/api/admin/discounts/{did}")
    def delete_discount(did: int, _: d.Admin, c: d.Conn):
        """Deja de poder usarse; quien ya lo tiene en su suscripción lo conserva (así funciona Stripe)."""
        r = discount_or_404(c, did)
        s = d.billing.client(c)
        if s is not None:
            try:
                s.request("POST", f"promotion_codes/{r['stripe_promo_id']}", {"active": False})
                s.request("DELETE", f"coupons/{r['stripe_coupon_id']}")
            except StripeError:
                pass   # ya no existía en Stripe: se borra igual del panel
        c.execute("DELETE FROM discounts WHERE id = ?", (did,))
        return {"ok": True}

    @app.post("/api/billing/discount")
    def check_discount(body: CheckIn, request: Request, c: d.Conn):
        """Comprueba un código antes de pagar (registro público y cambio de plan) y da el precio final."""
        key = "disc:" + (request.client.host if request.client else "unknown")
        if d.limiter.blocked(key):
            raise HTTPException(429, "Demasiados intentos. Espere unos minutos.")
        plan = None
        if body.plan_id is not None:
            plan = c.execute("SELECT * FROM plans WHERE id = ? AND active = 1", (body.plan_id,)).fetchone()
            if plan is None:
                raise HTTPException(404, "Plan no encontrado")
        try:
            r = resolve(c, body.code, plan or {"id": None, "currency": "eur"}, check_plan=plan is not None)
        except HTTPException:
            d.limiter.hit(key)   # evita probar códigos a ciegas
            raise
        if r is None:
            raise HTTPException(422, "Escribe el código")
        out = {"code": r["code"], "label": label(r), "plan_ids": plan_ids(r)}
        if plan is not None:
            period = "año" if plan["interval"] == "year" else "mes"
            out.update(plan=plan["name"], before=f"{money(plan['price_cents'], plan['currency'])}/{period}",
                       after=f"{money(discounted(r, plan['price_cents']), plan['currency'])}/{period}")
        return out

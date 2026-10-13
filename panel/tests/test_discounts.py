from __future__ import annotations

import time

from fastapi.testclient import TestClient

from tests.test_billing import H, FakeStripe, admin, setup_stripe, stripe_srv, subscription  # noqa: F401


def form_of(path, method="POST"):
    return [f for m, p, f in FakeStripe.calls if p == path and m == method]


def test_discount_codes(admin):  # noqa: F811
    setup_stripe(admin)
    basic = admin.post("/api/admin/plans", json={"name": "Básico", "price_cents": 1000, "max_devices": 3}, headers=H).json()
    pro = admin.post("/api/admin/plans", json={"name": "Pro", "price_cents": 2000, "max_devices": 20}, headers=H).json()
    new = lambda **kw: admin.post("/api/admin/discounts", json=kw, headers=H)  # noqa: E731
    # validación
    assert new(code="x", percent_off=10, duration="once").status_code == 422
    assert new(code="AMBOS", percent_off=10, amount_off=100, duration="once").status_code == 422
    assert new(code="NADA", duration="once").status_code == 422
    assert new(code="MESES", percent_off=10, duration="repeating").status_code == 422
    assert new(code="VIEJO", percent_off=10, duration="once", expires_at=int(time.time()) - 10).status_code == 422
    # 20 % durante 3 meses, sólo para Pro, máx. 50 usos
    r = new(code="verano20", percent_off=20, duration="repeating", months=3, max_redemptions=50, plan_ids=[pro["id"]]).json()
    assert r["code"] == "VERANO20" and r["label"] == "−20 % durante 3 meses" and r["plan_ids"] == [pro["id"]]
    co = form_of("coupons")[-1]
    assert co["percent_off"] == "20.0" and co["duration"] == "repeating" and co["duration_in_months"] == "3"
    assert co["applies_to[products][0]"].startswith("prod_")
    pc = form_of("promotion_codes")[-1]
    assert pc["code"] == "VERANO20" and pc["max_redemptions"] == "50" and pc["coupon"].startswith("co_")
    assert new(code="Verano20", percent_off=5, duration="once").status_code == 409            # repetido
    # 5 € para siempre, todos los planes
    r2 = new(code="SIEMPRE5", amount_off=500, duration="forever").json()
    assert r2["label"] == "−5,00 € para siempre" and form_of("coupons")[-1]["amount_off"] == "500"
    lst = admin.get("/api/admin/discounts").json()["discounts"]
    assert [x["code"] for x in lst] == ["SIEMPRE5", "VERANO20"] and lst[0]["redeemed"] == 0

    # el cliente lo comprueba y lo usa al contratar
    t = admin.post("/api/admin/tenants", json={"name": "Acme", "username": "acme", "password": "Temporal1"}, headers=H).json()
    boss = TestClient(admin.app)
    boss.post("/api/auth/login", json={"username": "acme", "password": "Temporal1"}, headers=H)
    boss.post("/api/me/password", json={"current": "Temporal1", "new": "Acme22222"}, headers=H)
    ok = boss.post("/api/billing/discount", json={"code": " verano20 ", "plan_id": pro["id"]}, headers=H).json()
    assert ok == {"code": "VERANO20", "label": "−20 % durante 3 meses", "plan_ids": [pro["id"]], "plan": "Pro",
                  "before": "20,00 €/mes", "after": "16,00 €/mes"}
    assert boss.post("/api/billing/discount", json={"code": "verano20"}, headers=H).json()["label"] == "−20 % durante 3 meses"
    bad = boss.post("/api/billing/discount", json={"code": "VERANO20", "plan_id": basic["id"]}, headers=H)
    assert bad.status_code == 422 and "plan" in bad.json()["detail"]
    assert boss.post("/api/billing/discount", json={"code": "NOEXISTE", "plan_id": pro["id"]}, headers=H).status_code == 422
    assert boss.post("/api/billing/checkout", json={"plan_id": basic["id"], "discount_code": "VERANO20"}, headers=H).status_code == 422
    boss.post("/api/billing/checkout", json={"plan_id": pro["id"], "discount_code": "verano20"}, headers=H)
    cs = form_of("checkout/sessions")[-1]
    verano_promo = next(p["id"] for p in FakeStripe.db["promos"].values() if p["code"] == "VERANO20")
    assert cs["discounts[0][promotion_code]"] == verano_promo
    assert "allow_promotion_codes" not in cs
    boss.post("/api/billing/checkout", json={"plan_id": basic["id"]}, headers=H)            # sin código: Stripe lo pide
    assert form_of("checkout/sessions")[-1]["allow_promotion_codes"] == "true"
    # cambio de plan de una suscripción activa con código
    subscription("sub_d1", t["id"], basic["stripe_price_id"])
    with admin.app.state.db.conn() as db:
        db.execute("UPDATE tenants SET stripe_subscription_id = 'sub_d1', billing_status = 'active' WHERE id = ?", (t["id"],))
    r = boss.post("/api/billing/checkout", json={"plan_id": pro["id"], "discount_code": "SIEMPRE5"}, headers=H).json()
    assert r.get("changed") and form_of("subscriptions/sub_d1")[-1]["discounts[0][promotion_code]"].startswith("promo_")

    # desactivar / caducar / borrar
    did = lst[1]["id"]
    assert admin.patch(f"/api/admin/discounts/{did}", json={"active": False}, headers=H).json()["active"] is False
    assert FakeStripe.db["promos"][verano_promo]["active"] is False
    assert boss.post("/api/billing/discount", json={"code": "VERANO20", "plan_id": pro["id"]}, headers=H).status_code == 422
    assert admin.delete(f"/api/admin/discounts/{did}", headers=H).json() == {"ok": True}
    assert any(p.startswith("coupons/") for m, p, f in FakeStripe.calls if m == "DELETE")
    assert [x["code"] for x in admin.get("/api/admin/discounts").json()["discounts"]] == ["SIEMPRE5"]
    # sólo el admin crea códigos
    assert boss.post("/api/admin/discounts", json={"code": "HACK", "percent_off": 100, "duration": "forever"}, headers=H).status_code == 403


def test_signup_with_code(admin):  # noqa: F811
    setup_stripe(admin)
    plan = admin.post("/api/admin/plans", json={"name": "Hogar", "price_cents": 300, "max_devices": 5}, headers=H).json()
    admin.put("/api/admin/billing/settings", json={"signup": True}, headers=H)
    admin.post("/api/admin/discounts", json={"code": "BIENVENIDA", "percent_off": 100, "duration": "once"}, headers=H)
    anon = TestClient(admin.app)
    ok = anon.post("/api/billing/discount", json={"code": "bienvenida", "plan_id": plan["id"]}, headers=H).json()
    assert ok["after"] == "0,00 €/mes" and ok["label"] == "−100 % en el primer pago"
    body = {"name": "Ana", "email": "ana@ejemplo.com", "username": "ana-vpn", "password": "Password1", "plan_id": plan["id"]}
    assert anon.post("/api/signup", json={**body, "discount_code": "MAL"}, headers=H).status_code == 422
    r = anon.post("/api/signup", json={**body, "discount_code": "BIENVENIDA"}, headers=H)
    assert r.status_code == 200 and form_of("checkout/sessions")[-1]["discounts[0][promotion_code]"].startswith("promo_")

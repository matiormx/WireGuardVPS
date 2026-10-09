from __future__ import annotations

import http.server
import itertools
import json
import threading
import time
import urllib.parse

import pytest
from fastapi.testclient import TestClient

from app import billing
from app.main import create_app

H = {"X-WGP": "1"}


class FakeStripe(http.server.BaseHTTPRequestHandler):
    """Lo justo de la API de Stripe para el panel."""
    db: dict = {}
    calls: list = []
    ids = itertools.count(1)

    @classmethod
    def reset(cls):
        cls.db = {"subscriptions": {}, "invoices": []}
        cls.calls = []

    def _reply(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _form(self):
        n = int(self.headers.get("Content-Length") or 0)
        return dict(urllib.parse.parse_qsl(self.rfile.read(n).decode())) if n else {}

    def _route(self, method):
        if self.headers.get("Authorization") != "Bearer sk_test_51Fake0123456789":
            return self._reply({"error": {"message": "Invalid API Key provided"}}, 401)
        path = urllib.parse.urlsplit(self.path).path.removeprefix("/v1/")
        form = self._form() if method == "POST" else {}
        FakeStripe.calls.append((method, path, form))
        nid = lambda p: f"{p}_{next(FakeStripe.ids)}"  # noqa: E731
        if path == "account":
            return self._reply({"id": "acct_1", "settings": {"dashboard": {"display_name": "Mi VPN"}}})
        if path == "webhook_endpoints" and method == "POST":
            return self._reply({"id": nid("we"), "secret": "whsec_test"})
        if path.startswith("webhook_endpoints/") and method == "DELETE":
            return self._reply({"deleted": True})
        if path in ("products", "prices", "customers"):
            return self._reply({"id": nid({"products": "prod", "prices": "price", "customers": "cus"}[path])})
        if path.startswith(("products/", "prices/")):
            return self._reply({"id": path.split("/")[1]})
        if path == "checkout/sessions":
            return self._reply({"id": nid("cs"), "url": "https://checkout.stripe.com/c/pay/cs_test"})
        if path == "billing_portal/sessions":
            return self._reply({"url": "https://billing.stripe.com/p/session/x"})
        if path.startswith("subscriptions/"):
            sid = path.split("/")[1]
            sub = FakeStripe.db["subscriptions"][sid]
            if method == "DELETE":
                sub["status"] = "canceled"
            if method == "POST":
                sub["items"]["data"][0]["price"]["id"] = form.get("items[0][price]", sub["items"]["data"][0]["price"]["id"])
                sub["cancel_at_period_end"] = form.get("cancel_at_period_end") == "true"
            return self._reply(sub)
        if path == "invoices":
            return self._reply({"data": FakeStripe.db["invoices"]})
        return self._reply({"error": {"message": f"no implementado: {path}"}}, 404)

    def do_GET(self):  # noqa: N802
        self._route("GET")

    def do_POST(self):  # noqa: N802
        self._route("POST")

    def do_DELETE(self):  # noqa: N802
        self._route("DELETE")

    def log_message(self, *a):
        pass


@pytest.fixture()
def stripe_srv(monkeypatch):
    FakeStripe.reset()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeStripe)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("STRIPE_API", f"http://127.0.0.1:{srv.server_port}")
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(k, raising=False)
    yield srv
    srv.shutdown()


@pytest.fixture()
def admin(tmp_path, monkeypatch, stripe_srv):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("WG_CONF_DIR", str(tmp_path / "wireguard"))
    monkeypatch.setenv("WG_ENDPOINT", "203.0.113.10")
    monkeypatch.setenv("SESSION_SECRET", "x")
    monkeypatch.setenv("DNS_ENABLED", "false")
    monkeypatch.setenv("CADDY_ADMIN", "")
    monkeypatch.setattr("app.wg.WireGuardManager.host_networks", lambda self: [])
    with TestClient(create_app()) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": "admin"}, headers=H)
        c.post("/api/me/password", json={"current": "admin", "new": "AdminPass1"}, headers=H)
        yield c


def subscription(sid, tenant_id, price, status="active", customer="cus_x", period_end=None, amount=None):
    sub = {"id": sid, "object": "subscription", "customer": customer, "status": status,
           "metadata": {"wgp_tenant": str(tenant_id)}, "cancel_at_period_end": False,
           "current_period_end": period_end or int(time.time()) + 30 * 86400,
           "items": {"data": [{"id": "si_1", "price": {"id": price, **({"unit_amount": amount, "recurring": {"interval": "month"}}
                                                                        if amount is not None else {})}}]}}
    FakeStripe.db["subscriptions"][sid] = sub
    return sub


def webhook(client, kind, obj, secret="whsec_test", event_id=None):
    payload = json.dumps({"id": event_id or f"evt_{time.time_ns()}", "type": kind, "data": {"object": obj}}).encode()
    return client.post("/api/billing/webhook", content=payload,
                       headers={"Stripe-Signature": billing.sign(payload, secret), "Content-Type": "application/json"})


def setup_stripe(admin):
    assert admin.put("/api/admin/billing/stripe", json={"secret_key": "sk_test_51Fake0123456789"}, headers=H).status_code == 409
    admin.put("/api/admin/settings", json={"main_domain": "vpn.ejemplo.com"}, headers=H)
    assert admin.put("/api/admin/billing/stripe", json={"secret_key": "pk_test_123456789012345"}, headers=H).status_code == 422
    assert admin.put("/api/admin/billing/stripe", json={"secret_key": "sk_test_WRONGWRONGWRONG"}, headers=H).status_code == 409
    st = admin.put("/api/admin/billing/stripe", json={"secret_key": "sk_test_51Fake0123456789"}, headers=H).json()
    assert st["stripe"] == {"connected": True, "live": False, "account": "Mi VPN", "webhook": True}
    hook = next(f for m, p, f in FakeStripe.calls if p == "webhook_endpoints")
    assert hook["url"] == "https://vpn.ejemplo.com/api/billing/webhook" and hook["enabled_events[0]"] == "checkout.session.completed"


def test_signature():
    body = b'{"a":1}'
    h = billing.sign(body, "whsec_x")
    assert billing.verify_signature(body, h, "whsec_x")
    assert not billing.verify_signature(body + b" ", h, "whsec_x")
    assert not billing.verify_signature(body, h, "whsec_y")
    assert not billing.verify_signature(body, billing.sign(body, "whsec_x", ts=int(time.time()) - 600), "whsec_x")
    assert not billing.verify_signature(body, "basura", "whsec_x")
    assert billing._flatten({"a": {"b": [1, {"c": True}]}, "d": None}) == [("a[b][0]", "1"), ("a[b][1][c]", "true")]
    assert billing.fmt_money(123456) == "1.234,56 €"


def test_plans_subscription_lifecycle(admin):
    setup_stripe(admin)
    basic = admin.post("/api/admin/plans", json={"name": "Básico", "price_cents": 500, "max_devices": 3}, headers=H).json()
    pro = admin.post("/api/admin/plans", json={"name": "Pro", "price_cents": 1500, "max_devices": 20, "max_forwards": 5,
                                               "max_services": 3, "max_members": 10, "allow_exits": True, "trial_days": 7},
                     headers=H).json()
    assert basic["price"] == "5,00 €" and basic["stripe_price_id"].startswith("price_")
    t = admin.post("/api/admin/tenants", json={"name": "Acme", "username": "acme", "password": "Temporal1"}, headers=H).json()
    boss = TestClient(admin.app)
    boss.post("/api/auth/login", json={"username": "acme", "password": "Temporal1"}, headers=H)
    boss.post("/api/me/password", json={"current": "Temporal1", "new": "Acme22222"}, headers=H)

    info = boss.get("/api/billing").json()
    assert info["plan"] is None and info["status"] == "none" and [p["name"] for p in info["plans"]] == ["Básico", "Pro"]
    r = boss.post("/api/billing/checkout", json={"plan_id": pro["id"]}, headers=H).json()
    assert r["url"].startswith("https://checkout.stripe.com/")
    cs = next(f for m, p, f in FakeStripe.calls if p == "checkout/sessions")
    assert cs["line_items[0][price]"] == pro["stripe_price_id"] and cs["subscription_data[trial_period_days]"] == "7"
    assert cs["success_url"] == "https://vpn.ejemplo.com/#/plan?pago=ok" and cs["client_reference_id"] == str(t["id"])
    cus = boss.get("/api/billing").json()
    assert cus["has_customer"]

    # Webhooks: firma obligatoria; el pago activa el plan y sus límites
    sub = subscription("sub_1", t["id"], pro["stripe_price_id"], status="trialing", customer=cs["customer"])
    assert webhook(boss, "customer.subscription.created", sub, secret="whsec_otro").status_code == 400
    assert webhook(boss, "checkout.session.completed", {"mode": "subscription", "client_reference_id": str(t["id"]),
                                                        "customer": cs["customer"], "subscription": "sub_1"}).status_code == 200
    info = boss.get("/api/billing").json()
    assert info["status"] == "trialing" and info["plan"]["name"] == "Pro"
    assert info["limits"] == {"devices": 20, "forwards": 5, "services": 3, "members": 10, "exits": True}
    ev = webhook(boss, "customer.subscription.updated", {**sub, "status": "active"}, event_id="evt_same")
    assert ev.json() == {"ok": True}
    assert webhook(boss, "customer.subscription.updated", {**sub, "status": "active"}, event_id="evt_same").json()["duplicate"]

    # Cambio de plan dentro del panel (prorrateo); los límites bajan
    r = boss.post("/api/billing/checkout", json={"plan_id": basic["id"]}, headers=H).json()
    assert r["changed"] and r["plan"]["name"] == "Básico" and r["limits"]["devices"] == 3 and not r["limits"]["exits"]
    upd = [f for m, p, f in FakeStripe.calls if p == "subscriptions/sub_1" and m == "POST"][-1]
    assert upd["items[0][price]"] == basic["stripe_price_id"] and upd["proration_behavior"] == "create_prorations"
    for i in range(3):
        boss.post("/api/devices", json={"name": f"D{i}"}, headers=H)
    assert boss.post("/api/devices", json={"name": "D4"}, headers=H).status_code == 409  # límite del plan
    assert boss.post("/api/forwards", json={"public_port": 20001, "target_ip": "10.252.1.2", "target_port": 80},
                     headers=H).status_code == 409

    # Impago: periodo de gracia y suspensión; el responsable puede entrar a pagar
    admin.put("/api/admin/billing/settings", json={"grace_days": 3}, headers=H)
    sub = FakeStripe.db["subscriptions"]["sub_1"]
    webhook(boss, "customer.subscription.updated", {**sub, "status": "past_due"})
    info = boss.get("/api/billing").json()
    assert info["status"] == "past_due" and info["suspend_at"] - info["past_due_since"] == 3 * 86400
    assert boss.get("/api/devices").status_code == 200     # aún en gracia
    bill = admin.app.state.billing
    bill.check_all(now=time.time() + 4 * 86400)
    assert boss.get("/api/devices").status_code == 402
    me = boss.get("/api/me").json()
    assert me["suspended"] and boss.get("/api/billing").json()["suspended"]
    assert boss.post("/api/billing/portal", headers=H).json()["url"].startswith("https://billing.stripe.com/")
    login = TestClient(admin.app).post("/api/auth/login", json={"username": "acme", "password": "Acme22222"}, headers=H)
    assert login.status_code == 200                         # puede entrar a pagar
    over = admin.get("/api/admin/billing").json()
    assert over["stats"]["suspended"] == 1 and over["attention"][0]["name"] == "Acme"
    FakeStripe.db["subscriptions"]["sub_1"]["status"] = "active"
    webhook(boss, "invoice.paid", {"customer": sub["customer"], "subscription": "sub_1"})
    assert boss.get("/api/devices").status_code == 200 and not boss.get("/api/billing").json()["suspended"]
    # Una suspensión manual del admin no se levanta con un pago
    admin.patch(f"/api/admin/tenants/{t['id']}", json={"enabled": False}, headers=H)
    webhook(boss, "customer.subscription.updated", FakeStripe.db["subscriptions"]["sub_1"])
    assert admin.get(f"/api/admin/tenants/{t['id']}").json()["enabled"] is False
    admin.patch(f"/api/admin/tenants/{t['id']}", json={"enabled": True}, headers=H)
    # Cancelación: suspendido al terminar
    webhook(boss, "customer.subscription.deleted", {**FakeStripe.db["subscriptions"]["sub_1"], "status": "canceled"})
    assert admin.get(f"/api/admin/tenants/{t['id']}").json()["enabled"] is False
    assert admin.get("/api/admin/billing").json()["stats"]["mrr_cents"] == 0

    # Cambiar el precio crea uno nuevo; el antiguo sigue reconociéndose
    old = basic["stripe_price_id"]
    new = admin.patch(f"/api/admin/plans/{basic['id']}", json={"price_cents": 700}, headers=H).json()
    assert new["stripe_price_id"] != old and new["price"] == "7,00 €"
    assert ("POST", f"prices/{old}", {"active": "false"}) in FakeStripe.calls
    webhook(boss, "customer.subscription.updated", subscription("sub_1", t["id"], old, "active", amount=500))
    assert boss.get("/api/billing").json()["plan"]["name"] == "Básico" and not boss.get("/api/billing").json()["suspended"]
    assert admin.delete(f"/api/admin/plans/{basic['id']}", headers=H).status_code == 409   # tiene clientes
    stats = admin.get("/api/admin/billing").json()["stats"]
    assert stats["active"] == 1 and stats["mrr"] == "5,00 €"  # sigue pagando el precio antiguo


def test_manual_plan_and_signup(admin):
    setup_stripe(admin)
    plan = admin.post("/api/admin/plans", json={"name": "Hogar", "price_cents": 300, "max_devices": 5, "max_members": 3},
                      headers=H).json()
    t = admin.post("/api/admin/tenants", json={"name": "Familia", "username": "familia", "password": "Temporal1"}, headers=H).json()
    r = admin.put(f"/api/admin/tenants/{t['id']}/plan", json={"plan_id": plan["id"]}, headers=H).json()
    assert r["status"] == "manual" and r["limits"]["devices"] == 5 and r["limits"]["members"] == 3
    admin.app.state.billing.check_all(now=time.time() + 400 * 86400)
    assert admin.get(f"/api/admin/tenants/{t['id']}").json()["enabled"] is True  # manual: nunca se suspende solo

    # Alta pública
    anon = TestClient(admin.app)
    assert anon.get("/api/signup").json() == {"enabled": False, "plans": []}
    assert anon.post("/api/signup", json={"name": "Nuevo", "email": "n@x.com", "username": "nuevo", "password": "Clave12345",
                                          "plan_id": plan["id"]}, headers=H).status_code == 403
    admin.put("/api/admin/billing/settings", json={"signup": True}, headers=H)
    assert [p["name"] for p in anon.get("/api/signup").json()["plans"]] == ["Hogar"]
    assert anon.post("/api/signup", json={"name": "X", "email": "malo", "username": "nuevo", "password": "Clave12345",
                                          "plan_id": plan["id"]}, headers=H).status_code == 422
    assert anon.post("/api/signup", json={"name": "X", "email": "n@x.com", "username": "familia", "password": "Clave12345",
                                          "plan_id": plan["id"]}, headers=H).status_code == 409
    r = anon.post("/api/signup", json={"name": "Nuevo Cliente", "email": "n@x.com", "username": "nuevo",
                                       "password": "Clave12345", "plan_id": plan["id"]}, headers=H)
    assert r.status_code == 200 and r.json()["url"].startswith("https://checkout.stripe.com/")
    cs = [f for m, p, f in FakeStripe.calls if p == "checkout/sessions"][-1]
    new_id = int(cs["client_reference_id"])
    assert cs["success_url"] == "https://vpn.ejemplo.com/#/signup/ok"
    tn = admin.get(f"/api/admin/tenants/{new_id}").json()
    assert tn["enabled"] is False and tn["billing_status"] == "pending" and tn["max_devices"] == 5
    # Antes de pagar puede entrar, pero sólo a su plan
    c2 = TestClient(admin.app)
    assert c2.post("/api/auth/login", json={"username": "nuevo", "password": "Clave12345"}, headers=H).status_code == 200
    assert c2.get("/api/devices").status_code == 402 and c2.get("/api/billing").json()["plan"]["name"] == "Hogar"
    # Pago confirmado: se activa
    subscription("sub_9", new_id, plan["stripe_price_id"], customer=cs["customer"])
    webhook(anon, "checkout.session.completed", {"mode": "subscription", "client_reference_id": str(new_id),
                                                 "customer": cs["customer"], "subscription": "sub_9",
                                                 "customer_details": {"email": "n@x.com"}})
    assert admin.get(f"/api/admin/tenants/{new_id}").json()["enabled"] is True
    assert c2.get("/api/devices").status_code == 200
    # Altas sin pagar caducan a las 48 h
    anon.post("/api/signup", json={"name": "Abandona", "email": "a@x.com", "username": "abandona", "password": "Clave12345",
                                   "plan_id": plan["id"]}, headers=H)
    gone = int([f for m, p, f in FakeStripe.calls if p == "checkout/sessions"][-1]["client_reference_id"])
    admin.app.state.billing.check_all(now=time.time() + 49 * 3600)
    assert admin.get(f"/api/admin/tenants/{gone}").status_code == 404
    assert admin.get(f"/api/admin/tenants/{new_id}").status_code == 200

    # Facturas
    FakeStripe.db["invoices"] = [{"id": "in_1", "number": "A-0001", "created": 1, "total": 300, "currency": "eur",
                                  "status": "paid", "hosted_invoice_url": "https://invoice.stripe.com/i/1", "invoice_pdf": "https://pdf"}]
    inv = c2.get("/api/billing/invoices").json()["invoices"]
    assert inv[0]["total"] == "3,00 €" and inv[0]["number"] == "A-0001"
    # Un cliente no ve la facturación de otro ni la del admin
    assert c2.get(f"/api/billing?tenant_id={t['id']}").json()["plan"]["name"] == "Hogar"  # tenant_id ajeno se ignora
    assert c2.get("/api/admin/billing").status_code == 403
    # Borrar un cliente cancela su suscripción en Stripe
    assert admin.delete(f"/api/admin/tenants/{new_id}", headers=H).status_code == 200
    assert ("DELETE", "subscriptions/sub_9", {}) in FakeStripe.calls


def test_free_tenants(admin):
    setup_stripe(admin)
    plan = admin.post("/api/admin/plans", json={"name": "Pro", "price_cents": 1500, "max_devices": 20, "max_forwards": 5},
                      headers=H).json()
    # Alta directa como gratuito
    f = admin.post("/api/admin/tenants", json={"name": "Mi casa", "username": "micasa", "password": "Temporal1", "free": True},
                   headers=H).json()
    assert f["billing_status"] == "free"
    boss = TestClient(admin.app)
    boss.post("/api/auth/login", json={"username": "micasa", "password": "Temporal1"}, headers=H)
    boss.post("/api/me/password", json={"current": "Temporal1", "new": "MiCasa2222"}, headers=H)
    info = boss.get("/api/billing").json()
    assert info["status"] == "free" and info["plans"] == []
    assert boss.post("/api/billing/checkout", json={"plan_id": plan["id"]}, headers=H).status_code == 409
    # Gratuito con los límites de un plan
    r = admin.put(f"/api/admin/tenants/{f['id']}/plan", json={"plan_id": plan["id"], "free": True}, headers=H).json()
    assert r["status"] == "free" and r["plan"]["name"] == "Pro" and r["limits"]["devices"] == 20

    # Un cliente que pagaba pasa a gratuito: se cancela su suscripción y no vuelve a suspenderse
    t = admin.post("/api/admin/tenants", json={"name": "Proyecto", "username": "proyecto", "password": "Temporal1"}, headers=H).json()
    subscription("sub_p", t["id"], plan["stripe_price_id"], status="past_due", customer="cus_p")
    webhook(boss, "customer.subscription.updated", FakeStripe.db["subscriptions"]["sub_p"])
    admin.app.state.billing.check_all(now=time.time() + 30 * 86400)
    assert admin.get(f"/api/admin/tenants/{t['id']}").json()["enabled"] is False
    r = admin.put(f"/api/admin/tenants/{t['id']}/plan", json={"plan_id": plan["id"], "free": True}, headers=H).json()
    assert r["status"] == "free" and not r["suspended"]
    assert ("DELETE", "subscriptions/sub_p", {}) in FakeStripe.calls
    assert admin.get(f"/api/admin/tenants/{t['id']}").json()["enabled"] is True
    admin.app.state.billing.check_all(now=time.time() + 400 * 86400)
    assert admin.get(f"/api/admin/tenants/{t['id']}").json()["enabled"] is True
    stats = admin.get("/api/admin/billing").json()["stats"]
    assert stats["free"] == 2 and stats["mrr_cents"] == 0
    # Quitar la marca de gratuito
    r = admin.put(f"/api/admin/tenants/{t['id']}/plan", json={"plan_id": plan["id"]}, headers=H).json()
    assert r["status"] == "manual"
    r = admin.put(f"/api/admin/tenants/{t['id']}/plan", json={"plan_id": None}, headers=H).json()
    assert r["status"] == "none" and len(r["plans"]) == 1


def test_checkout_from_public_site_returns_there(admin):
    setup_stripe(admin)
    plan = admin.post("/api/admin/plans", json={"name": "Hogar", "price_cents": 499, "max_devices": 5}, headers=H).json()
    admin.put("/api/admin/site", json={"domains": ["mivpn.com"], "enabled": True}, headers=H)
    admin.put("/api/admin/billing/settings", json={"signup": True}, headers=H)
    anon = TestClient(admin.app)
    r = anon.post("/api/signup", json={"name": "Nuevo", "email": "n@x.com", "username": "nuevo", "password": "Clave12345",
                                       "plan_id": plan["id"]}, headers={**H, "Host": "mivpn.com"})
    assert r.status_code == 200
    cs = [f for m, p, f in FakeStripe.calls if p == "checkout/sessions"][-1]
    assert cs["success_url"] == "https://mivpn.com/app#/signup/ok" and cs["cancel_url"] == "https://mivpn.com/app#/signup"

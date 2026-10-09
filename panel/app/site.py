"""Página pública: presentación del servicio, planes y acceso.

Se sirve en el puerto 443 (vía Caddy, con certificado automático) en los
dominios que el admin configure en Ajustes › Página pública, distintos del
dominio del panel o de WireGuard. En esos dominios:
  /        la página de presentación (HTML generado aquí, sin JavaScript)
  /app     el panel (login, registro y la app), con la misma sesión

Todo el texto configurable se escapa al generar el HTML.

Sin `from __future__ import annotations`: FastAPI evalúa las dependencias de `deps`.
"""
import datetime as dt
import html
import re
import sqlite3
import urllib.parse

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .billing import fmt_money
from .db import get_setting, set_setting

MAX_DOMAINS = 3
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
DEFAULTS = {
    "site_title": "WireGuard Cloud",
    "site_headline": "Tu red privada, en todas partes",
    "site_subtitle": ("Conecta tus dispositivos, tu oficina y tu casa en una red privada y cifrada. "
                      "Navega sin anuncios ni rastreadores, con filtros para la familia, desde cualquier lugar."),
}


def esc(text) -> str:
    return html.escape(str(text or ""), quote=True)


class SiteIn(BaseModel):
    enabled: bool | None = None
    domains: list[str] | None = Field(default=None, max_length=MAX_DOMAINS)
    title: str | None = Field(default=None, max_length=60)
    headline: str | None = Field(default=None, max_length=120)
    subtitle: str | None = Field(default=None, max_length=400)
    email: str | None = Field(default=None, max_length=254)
    legal: str | None = Field(default=None, max_length=4000)


def config(c: sqlite3.Connection) -> dict:
    return {
        "enabled": get_setting(c, "site_enabled") == "1",
        "domains": (get_setting(c, "site_domains") or "").split(),
        "title": get_setting(c, "site_title") or DEFAULTS["site_title"],
        "headline": get_setting(c, "site_headline") or DEFAULTS["site_headline"],
        "subtitle": get_setting(c, "site_subtitle") or DEFAULTS["site_subtitle"],
        "email": get_setting(c, "site_email") or "",
        "legal": get_setting(c, "site_legal") or "",
    }


# --------------------------------------------------------------------------- HTML
ICONS = {
    "lock": '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/>',
    "globe": '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/>',
    "users": '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/>',
    "router": '<rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 17h.01M10 17h.01M15 13V7M12 4.5a4.5 4.5 0 0 1 6 0"/>',
    "server": '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01M6 17h.01"/>',
    "phone": '<rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/>',
    "bell": '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "plug": '<path d="M9 2v6M15 2v6M6 8h12v4a6 6 0 0 1-12 0z"/><path d="M12 18v4"/>',
}


def svg(name: str) -> str:
    return (f'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
            f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{ICONS[name]}</svg>')


def flag(code: str) -> str:
    return "".join(chr(0x1F1A5 + ord(ch)) for ch in code) if re.fullmatch(r"[A-Z]{2}", code or "") else "🌐"


def plan_features(p: sqlite3.Row) -> list[str]:
    out = [f"{p['max_devices']} dispositivos"]
    if p["max_members"]:
        out.append(f"{p['max_members']} usuarios")
    if p["max_forwards"]:
        out.append(f"{p['max_forwards']} puertos abiertos")
    if p["max_services"]:
        out.append(f"{p['max_services']} servicios con HTTPS")
    if p["allow_exits"]:
        out.append("Salidas por otros países")
    out.append("Filtros de anuncios y familia")
    if p["trial_days"]:
        out.append(f"{p['trial_days']} días de prueba gratis")
    return out


def render(c: sqlite3.Connection, https_enabled: bool) -> str:
    cfg = config(c)
    signup = get_setting(c, "billing_signup") == "1" and bool(get_setting(c, "stripe_secret_key"))
    plans = c.execute("""SELECT * FROM plans WHERE active = 1 AND public = 1 AND price_cents > 0
                         ORDER BY sort, price_cents""").fetchall()
    exits = c.execute("SELECT name, country FROM exits WHERE enabled = 1 ORDER BY name").fetchall()
    main_country = get_setting(c, "main_exit_country") or ""
    title, email = cfg["title"], cfg["email"]

    features = [
        ("lock", "Red privada cifrada", "Tus dispositivos se ven entre sí como en la misma oficina, cifrados con WireGuard, el protocolo VPN más rápido y moderno."),
        ("shield", "Sin anuncios ni rastreadores", "Bloqueo de publicidad, malware y rastreo para toda la red, y filtros de contenido para la familia."),
        ("server", "Tu propio DNS", "Pon nombre a tus equipos (nas, impresora…) y elige cómo se resuelve todo lo demás."),
        ("router", "Oficinas completas", "Conecta el router de tu oficina o de casa (MikroTik, OpenWrt…) y llega a todos sus equipos."),
    ]
    if https_enabled:
        features.append(("globe", "Publica tus servicios", "Accede a tu NAS, cámaras o Home Assistant desde Internet con tu dominio y HTTPS, con contraseña opcional."))
    features.append(("plug", "Puertos abiertos", "Escritorio remoto, cámaras o juegos: abre un puerto hacia un equipo de tu red en un minuto."))
    if exits:
        countries = " ".join(flag(e["country"]) for e in exits)
        features.append(("globe", "Navega desde otros países", f"Elige por qué país sale cada dispositivo a Internet: {countries}"))
    features += [
        ("users", "Para equipos y familias", "Invita a cada persona con su cuenta: cada uno ve sus dispositivos y tú lo ves todo."),
        ("bell", "Actividad y avisos", "Gráficas de uso y avisos por notificación, Telegram o email si se cae un router."),
        ("phone", "En todos tus dispositivos", "iPhone, Android, Windows, Mac y Linux con la app oficial de WireGuard: escanea un QR y listo."),
    ]

    def plan_card(p: sqlite3.Row, featured: bool) -> str:
        period = "año" if p["interval"] == "year" else "mes"
        cta = (f'<a class="btn {"primary" if featured else ""} block" href="/app#/signup?plan={int(p["id"])}">Contratar</a>' if signup
               else f'<a class="btn {"primary" if featured else ""} block" href="mailto:{esc(email)}?subject={esc(urllib.parse.quote("Plan " + p["name"]))}">Contactar</a>'
               if email else '<a class="btn block" href="/app">Entrar</a>')
        items = "".join(f"<li>{svg('check')}{esc(f)}</li>" for f in plan_features(p))
        return (f'<div class="plan{" featured" if featured else ""}">'
                + ('<span class="tag">Más elegido</span>' if featured else "")
                + f'<h3>{esc(p["name"])}</h3>'
                + (f'<p class="muted">{esc(p["description"])}</p>' if p["description"] else "")
                + f'<div class="price">{esc(fmt_money(p["price_cents"], p["currency"]))}<span>/{period}</span></div>'
                + f'<ul>{items}</ul>{cta}</div>')

    featured_idx = len(plans) // 2 if len(plans) >= 3 else -1
    plans_html = "".join(plan_card(p, i == featured_idx) for i, p in enumerate(plans))
    feat_html = "".join(f'<div class="feature"><div class="ficon">{svg(i)}</div><h3>{esc(t)}</h3><p>{esc(d)}</p></div>'
                        for i, t, d in features)
    signup_btn = '<a class="btn primary" href="/app#/signup">Crear cuenta</a>' if signup else ""
    hero_cta = ('<a class="btn primary lg" href="#planes">Ver planes</a>' if plans else
                (f'<a class="btn primary lg" href="mailto:{esc(email)}">Contactar</a>' if email else ""))
    legal = "".join(f"<p>{esc(line)}</p>" for line in cfg["legal"].splitlines() if line.strip())
    year = dt.date.today().year
    location = f" · Servidores en {flag(main_country)}" if main_country else ""

    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#0b0d14" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)">
<title>{esc(title)} · {esc(cfg["headline"])}</title>
<meta name="description" content="{esc(cfg["subtitle"])}">
<meta property="og:title" content="{esc(title)}">
<meta property="og:description" content="{esc(cfg["subtitle"])}">
<meta property="og:type" content="website">
<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/static/icons/apple-touch-icon.png">
<link rel="stylesheet" href="/static/site.css">
</head>
<body>
<header class="top">
  <div class="wrap row">
    <a class="logo" href="/"><span class="mark">{svg("lock")}</span>{esc(title)}</a>
    <nav>
      <a href="#funciones" class="hide-sm">Funciones</a>
      {'<a href="#planes" class="hide-sm">Planes</a>' if plans else ""}
      <a class="btn ghost" href="/app">Entrar</a>
      {signup_btn.replace('class="btn primary"', 'class="btn primary hide-xs"')}
    </nav>
  </div>
</header>
<main>
  <section class="hero">
    <div class="wrap">
      <p class="eyebrow">VPN WireGuard · Red privada{esc(location)}</p>
      <h1>{esc(cfg["headline"])}</h1>
      <p class="lead">{esc(cfg["subtitle"])}</p>
      <div class="ctas">{hero_cta}<a class="btn lg" href="/app">Entrar a mi cuenta</a></div>
    </div>
  </section>
  <section id="funciones" class="section">
    <div class="wrap">
      <h2>Todo lo que necesitas</h2>
      <p class="muted center">Sin instalar nada raro: la app oficial de WireGuard y un panel sencillo desde el móvil o el ordenador.</p>
      <div class="features">{feat_html}</div>
    </div>
  </section>
  <section class="section alt">
    <div class="wrap">
      <h2>Así de fácil</h2>
      <ol class="steps">
        <li><b>Elige tu plan</b><span>Pago seguro con tarjeta; cancela cuando quieras.</span></li>
        <li><b>Añade tus dispositivos</b><span>En el panel, «Añadir dispositivo» y escanea el QR con la app WireGuard.</span></li>
        <li><b>Conectado</b><span>Tu red privada funciona en casa, en la oficina o de viaje.</span></li>
      </ol>
    </div>
  </section>
  {f'''<section id="planes" class="section">
    <div class="wrap">
      <h2>Planes</h2>
      <p class="muted center">Precios con impuestos según tu país. Sin permanencia.</p>
      <div class="plans">{plans_html}</div>
    </div>
  </section>''' if plans else ""}
  <section class="section cta-end">
    <div class="wrap center">
      <h2>¿Ya tienes cuenta?</h2>
      <p class="muted">Entra para gestionar tus dispositivos, tu red y tu plan.</p>
      <div class="ctas center"><a class="btn primary lg" href="/app">Entrar</a>{signup_btn.replace('btn primary', 'btn lg')}</div>
    </div>
  </section>
</main>
<footer>
  <div class="wrap">
    <div class="row foot">
      <span>© {year} {esc(title)}</span>
      {f'<a href="mailto:{esc(email)}">{esc(email)}</a>' if email else ""}
    </div>
    {f'<div class="legal">{legal}</div>' if legal else ""}
  </div>
</footer>
</body>
</html>"""


# --------------------------------------------------------------------------- API
def register(app: FastAPI, d) -> None:

    def state(c: sqlite3.Connection) -> dict:
        cfg = config(c)
        cfg["server_ips"] = sorted(d.doms.expected_ips())
        cfg["url"] = f"https://{cfg['domains'][0]}" if cfg["domains"] else None
        cfg["has_plans"] = bool(c.execute("SELECT 1 FROM plans WHERE active = 1 AND public = 1 AND price_cents > 0").fetchone())
        cfg["signup"] = get_setting(c, "billing_signup") == "1"
        return cfg

    @app.get("/api/admin/site")
    def get_site(_: d.Admin, c: d.Conn):
        return state(c)

    @app.put("/api/admin/site")
    def put_site(body: SiteIn, _: d.Admin, c: d.Conn):
        if body.domains is not None:
            current = (get_setting(c, "site_domains") or "").split()
            clean = []
            for raw in body.domains:
                host = d.clean_host(raw)
                if not host or host in clean:
                    continue
                if host not in current and d.doms.taken(c, host):
                    raise HTTPException(409, f"{host} ya lo usa el panel, un cliente o un servicio")
                clean.append(host)
            set_setting(c, "site_domains", " ".join(clean))
        if body.email is not None:
            email = body.email.strip()
            if email and not EMAIL_RE.match(email):
                raise HTTPException(422, "Email de contacto no válido")
            set_setting(c, "site_email", email)
        for key in ("title", "headline", "subtitle", "legal"):
            value = getattr(body, key)
            if value is not None:
                set_setting(c, f"site_{key}", value.strip())
        if body.enabled is not None:
            if body.enabled and not (get_setting(c, "site_domains") or "").split():
                raise HTTPException(422, "Indica el dominio de la página")
            set_setting(c, "site_enabled", "1" if body.enabled else "0")
        return state(c)

    @app.get("/api/admin/site/status")
    async def site_status(_: d.Admin, c: d.Conn):
        import asyncio
        domains = (get_setting(c, "site_domains") or "").split()
        return await asyncio.to_thread(d.doms.status, domains[0] if domains else None)

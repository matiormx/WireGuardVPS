/* ==========================================================================
   WireGuard Cloud — SPA sin dependencias
   - Admin: panel, clientes (redes /24), dispositivos de cada cliente
   - Cliente: su red privada y sus dispositivos
   Todo el DOM se construye con textContent (sin innerHTML con datos) => sin XSS.
   ========================================================================== */
"use strict";

const $app = document.getElementById("app");
const state = { me: null, timer: null, installPrompt: null, brand: { title: "WireGuard Cloud", tenant: false } };
const REFRESH_MS = 10000;

/* ------------------------------------------------------------------ iconos */
const SVG_NS = "http://www.w3.org/2000/svg";
const ICONS = {
  logo: '<path d="M4 7l4.5 11L12 10l3.5 8L20 7"/>',
  dashboard: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>',
  network: '<rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M5 16v-3h14v3M12 8v5"/>',
  devices: '<rect x="2" y="4" width="14" height="10" rx="2"/><path d="M6 18h6M9 14v4"/><rect x="17" y="8" width="5" height="12" rx="1.5"/>',
  key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3L21 2M16 7l3 3M19 4l2 2"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  qr: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14v.01M14 20h.01M17 20h4v-3"/>',
  edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
  trash: '<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>',
  power: '<path d="M18.36 6.64a9 9 0 1 1-12.73 0M12 2v10"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
  copy: '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  refresh: '<path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15"/>',
  x: '<path d="M18 6L6 18M6 6l12 12"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
  activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
  arrows: '<path d="M7 17L17 7M7 7h10v10"/>',
  server: '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01M6 17h.01"/>',
  alert: '<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01"/>',
  menu: '<path d="M3 12h18M3 6h18M3 18h18"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 4 10 15 15 0 0 1-4 10 15 15 0 0 1-4-10 15 15 0 0 1 4-10z"/>',
  eye: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12z"/><circle cx="12" cy="12" r="3"/>',
  ban: '<circle cx="12" cy="12" r="10"/><path d="M4.9 4.9l14.2 14.2"/>',
  bug: '<rect x="8" y="6" width="8" height="14" rx="4"/><path d="M19 7l-3 2M5 7l3 2M19 19l-3-2M5 19l3-2M20 13h-4M4 13h4M10 4l1 2M14 4l-1 2"/>',
  heart: '<path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.7l-1-1.1a5.5 5.5 0 0 0-7.8 7.8l1 1.1L12 21l7.8-7.5 1-1.1a5.5 5.5 0 0 0 0-7.8z"/>',
  dice: '<rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="8" cy="8" r="1.2"/><circle cx="16" cy="16" r="1.2"/><circle cx="12" cy="12" r="1.2"/>',
  check: '<path d="M20 6L9 17l-5-5"/>',
  router: '<rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 17h.01M10 17h.01M15 13V7M12 4.5a4.5 4.5 0 0 1 6 0M10 2.5a7.5 7.5 0 0 1 10 0"/>',
  share: '<path d="M4 12v7a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7"/><path d="M16 6l-4-4-4 4"/><path d="M12 2v13"/>',
  fingerprint: '<path d="M2 12C2 6.5 6.5 2 12 2a10 10 0 0 1 8 4"/><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M9 6.8a6 6 0 0 1 9 5.2c0 .47 0 1.17-.02 2"/>',
};

function icon(name) {
  const s = document.createElementNS(SVG_NS, "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("fill", "none");
  s.setAttribute("stroke", "currentColor");
  s.setAttribute("stroke-width", "2");
  s.setAttribute("stroke-linecap", "round");
  s.setAttribute("stroke-linejoin", "round");
  s.setAttribute("aria-hidden", "true");
  s.innerHTML = ICONS[name] || ""; // constantes propias, nunca datos de usuario
  return s;
}

/* ------------------------------------------------------------------ DOM */
function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "style") Object.assign(el.style, v);
    else if (k === "value") el.value = v; // también para <textarea>
    else if (k in el && typeof v !== "string") el[k] = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  append(el, children);
  return el;
}
function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
// Sustituye el contenido ignorando null/false (el append nativo los pintaría como texto).
function fill(el, ...children) { return append(clear(el), children); }

/* ------------------------------------------------------------------ utilidades */
function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), u.length - 1);
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`;
}
function ago(ts) {
  if (!ts) return "Nunca";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return `hace ${s} s`;
  if (s < 3600) return `hace ${Math.floor(s / 60)} min`;
  if (s < 86400) return `hace ${Math.floor(s / 3600)} h`;
  return `hace ${Math.floor(s / 86400)} d`;
}
function fmtDate(ts) {
  return new Date(ts * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}
function genPassword(len = 14) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  const buf = new Uint32Array(len);
  crypto.getRandomValues(buf);
  return Array.from(buf, (x) => alphabet[x % alphabet.length]).join("");
}
function slugify(s) {
  return s.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-").replace(/^[-._]+|[-._]+$/g, "").slice(0, 32);
}
async function copyText(text, label = "Copiado al portapapeles") {
  try {
    await navigator.clipboard.writeText(text);
    toast(label);
  } catch {
    toast("No se pudo copiar (el navegador lo bloquea sin HTTPS)", "err");
  }
}
function initials(name) {
  return (name || "?").split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join("");
}

/* ------------------------------------------------------------------ API */
class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}
function errorMessage(data, status) {
  if (!data) return `Error ${status}`;
  if (typeof data.detail === "string") return data.detail;
  if (Array.isArray(data.detail)) {
    return data.detail.map((d) => `${(d.loc || []).slice(-1)[0] || ""}: ${d.msg}`).join(" · ");
  }
  return `Error ${status}`;
}
async function api(method, path, body) {
  const opts = { method, headers: { "X-WGP": "1" }, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const isJson = (res.headers.get("content-type") || "").includes("application/json");
  const data = isJson ? await res.json() : await res.text();
  if (res.status === 401 && path !== "/api/auth/login") {
    state.me = null;
    render();
    throw new ApiError("Sesión caducada", 401);
  }
  if (res.status === 403 && data && data.detail === "password_change_required") {
    if (state.me) state.me.must_change = true;
    render();
    throw new ApiError("Debe cambiar la contraseña", 403);
  }
  if (!res.ok) throw new ApiError(errorMessage(isJson ? data : null, res.status), res.status);
  return data;
}

/* ------------------------------------------------------------------ toasts y modales */
function toast(msg, kind = "ok") {
  const el = h("div", { class: `toast ${kind}`, role: "status" }, msg);
  document.getElementById("toasts").append(el);
  setTimeout(() => el.remove(), 3800);
}

function modal({ title, body, actions = [], wide = false, onClose }) {
  const close = () => { overlay.remove(); document.removeEventListener("keydown", onKey); onClose && onClose(); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  const box = h("div", { class: `modal${wide ? " wide" : ""}`, role: "dialog", "aria-modal": "true" },
    h("div", { class: "modal-head" },
      h("h2", { text: title }),
      h("button", { class: "btn ghost icon", "aria-label": "Cerrar", onClick: close }, icon("x"))),
    h("div", { class: "modal-body" }, body),
    actions.length ? h("div", { class: "modal-foot" }, actions) : null,
  );
  const overlay = h("div", { class: "overlay", onMousedown: (e) => { if (e.target === overlay) close(); } }, box);
  document.addEventListener("keydown", onKey);
  document.body.append(overlay);
  const first = box.querySelector("input, select, textarea");
  if (first) setTimeout(() => first.focus(), 30);
  return { close, box };
}

function formModal({ title, fields, submitLabel = "Guardar", danger = false, onSubmit }) {
  const form = h("form", { class: "form-grid", onSubmit: async (e) => {
    e.preventDefault();
    btn.disabled = true;
    try {
      await onSubmit(new FormData(form), m);
      m.close();
    } catch (err) {
      toast(err.message, "err");
    } finally {
      btn.disabled = false;
    }
  } }, fields);
  const btn = h("button", { class: `btn ${danger ? "danger" : "primary"}`, type: "submit" }, submitLabel);
  form.append(h("div", { class: "modal-foot full", style: { padding: "6px 0 0" } },
    h("button", { class: "btn", type: "button", onClick: () => m.close() }, "Cancelar"), btn));
  const m = modal({ title, body: form });
  return m;
}

function confirmDialog({ title, message, confirmLabel = "Confirmar", danger = true }) {
  return new Promise((resolve) => {
    let done = false;
    const m = modal({
      title,
      body: h("p", { style: { margin: 0, color: "var(--muted)" } }, message),
      actions: [
        h("button", { class: "btn", onClick: () => m.close() }, "Cancelar"),
        h("button", { class: `btn ${danger ? "danger" : "primary"}`, onClick: () => { done = true; m.close(); resolve(true); } }, confirmLabel),
      ],
      onClose: () => { if (!done) resolve(false); },
    });
  });
}

let fieldSeq = 0;
function field(label, input, help) {
  // Etiqueta asociada al campo (for/id): el autorrelleno de iOS/Android y los
  // lectores de pantalla la usan para entender qué es cada campo.
  if (!input.id) input.id = `f${++fieldSeq}-${input.name || "campo"}`;
  return h("div", { class: "field" }, h("label", { text: label, for: input.id }), input,
    help ? h("div", { class: "help", text: help }) : null);
}
function input(props) { return h("input", { class: "input", ...props }); }
function switchEl(name, checked, label) {
  return h("label", { class: "switch" },
    h("input", { type: "checkbox", name, checked: !!checked }),
    h("span", { class: "track" }),
    label ? h("span", { text: label }) : null);
}
function passwordField(name, label, help) {
  const inp = input({ name, type: "text", required: true, minlength: "8", autocomplete: "new-password", value: genPassword() });
  return h("div", { class: "field full" },
    h("label", { text: label }),
    h("div", { class: "input-group" }, inp,
      h("button", { class: "btn icon", type: "button", title: "Generar", onClick: () => { inp.value = genPassword(); } }, icon("refresh")),
      h("button", { class: "btn icon", type: "button", title: "Copiar", onClick: () => copyText(inp.value) }, icon("copy"))),
    help ? h("div", { class: "help", text: help }) : null);
}
function spinnerBlock() { return h("div", { class: "boot", style: { minHeight: "200px" } }, h("div", { class: "spinner" })); }

/* ------------------------------------------------------------------ router */
function route() {
  const parts = (location.hash.replace(/^#\/?/, "") || "").split("/").filter(Boolean);
  return parts;
}
function go(hash) { if (location.hash !== hash) location.hash = hash; else render(); }
window.addEventListener("hashchange", () => render());

function stopTimer() { if (state.timer) { clearInterval(state.timer); state.timer = null; } }
function isEditing() {
  const el = document.activeElement;
  return Boolean(el && ["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName));
}
function every(fn) {
  stopTimer();
  state.timer = setInterval(() => { if (!document.hidden && !isEditing()) fn(true); }, REFRESH_MS);
}

async function render() {
  stopTimer();
  if (state.me) stopConditionalPasskey();
  if (!state.me) return loginView();
  if (state.me.must_change) return forcePasswordView();
  const [section, id, sub] = route();
  const isAdmin = state.me.role === "admin";
  const main = shell(section || "home");
  if (!state.passkeyChecked) {
    state.passkeyChecked = true;
    setTimeout(suggestPasskey, 900);
  }
  try {
    if (section === "account") return accountView(main);
    if (section === "settings" && isAdmin) return await settingsView(main);
    if (isAdmin) {
      if (section === "clients" && id && sub === "filters") return await filtersView(main, Number(id));
      if (section === "clients" && id && sub === "dns") return await zoneView(main, Number(id));
      if (section === "clients" && id && sub === "services") return await servicesView(main, Number(id));
      if (section === "clients" && id) return await clientDetailView(main, Number(id));
      if (section === "clients") return await clientsView(main);
      return await dashboardView(main);
    }
    if (section === "filters") return await filtersView(main, state.me.id);
    if (section === "dns") return await zoneView(main, state.me.id);
    if (section === "services") return await servicesView(main, state.me.id);
    return await tenantHomeView(main);
  } catch (err) {
    if (err.status !== 401) {
      fill(main, h("div", { class: "card empty" }, icon("alert"), h("h2", { text: "No se pudo cargar" }), h("p", { text: err.message })));
    }
  }
}

/* ------------------------------------------------------------------ shell */
function brand() {
  return h("div", { class: "brand" }, h("div", { class: "logo" }, icon("logo")), h("span", { text: state.brand.title }));
}

function shell(active) {
  const isAdmin = state.me.role === "admin";
  const links = isAdmin
    ? [["home", "#/", "dashboard", "Panel"], ["clients", "#/clients", "users", "Clientes"], ["settings", "#/settings", "globe", "Ajustes"], ["account", "#/account", "key", "Cuenta"]]
    : [["home", "#/", "network", "Mi red"], ["dns", "#/dns", "server", "DNS"], ["services", "#/services", "globe", "Servicios"],
      ["filters", "#/filters", "shield", "Filtros"],
      ["account", "#/account", "key", "Cuenta"]];
  const sidebar = h("aside", { class: "sidebar" },
    brand(),
    h("nav", { class: "nav" }, links.map(([key, href, ic, label]) =>
      h("a", { href, class: key === active ? "active" : null, onClick: () => sidebar.classList.remove("open") }, icon(ic), label)),
      isStandalone() ? null : h("a", { href: "#", class: "install-link", onClick: (e) => { e.preventDefault(); sidebar.classList.remove("open"); installApp(); } },
        icon("download"), "Instalar app")),
    h("div", { class: "spacer" }),
    h("div", { class: "userbox" },
      h("div", { class: "avatar", text: initials(state.me.name || state.me.username) }),
      h("div", { class: "who" }, h("b", { text: state.me.name || state.me.username }), h("span", { text: isAdmin ? "Administrador" : "Cliente" })),
      h("button", { class: "btn ghost icon", title: "Cerrar sesión", onClick: logout }, icon("logout"))),
  );
  const main = h("main", { class: "main" }, spinnerBlock());
  const topbar = h("div", { class: "topbar" }, brand(),
    h("button", { class: "btn ghost icon", "aria-label": "Menú", onClick: () => sidebar.classList.toggle("open") }, icon("menu")));
  clear($app);
  $app.className = "";
  $app.append(h("div", { class: "layout" }, sidebar, h("div", null, topbar, main)));
  return main;
}

function pageHead(title, sub, actions, crumbs) {
  return h("div", { class: "page-head" },
    h("div", null,
      crumbs ? h("div", { class: "crumbs" }, crumbs) : null,
      h("h1", { text: title }),
      sub ? h("div", { class: "sub" }, sub) : null),
    actions ? h("div", { class: "cell-flex" }, actions) : null);
}

async function logout() {
  try { await api("POST", "/api/auth/logout"); } catch { /* ignorar */ }
  state.me = null;
  location.hash = "#/";
  render();
}

/* ------------------------------------------------------------------ login */
function loginView() {
  $app.className = "";
  const err = h("div", { class: "help", style: { color: "var(--danger)", minHeight: "18px" } });
  const btn = h("button", { class: "btn primary block", type: "submit" }, "Entrar");
  // Formulario de inicio de sesión «de libro» para que iOS no lo tome por un alta:
  // method/action, ids, etiquetas asociadas, autocomplete username/current-password.
  const form = h("form", { id: "login-form", method: "post", action: "/", autocomplete: "on", onSubmit: async (e) => {
    e.preventDefault();
    stopConditionalPasskey();
    err.textContent = "";
    btn.disabled = true;
    const fd = new FormData(form);
    try {
      await api("POST", "/api/auth/login", { username: fd.get("username"), password: fd.get("password") });
      state.me = await api("GET", "/api/me");
      render();
    } catch (ex) {
      err.textContent = ex.message;
    } finally {
      btn.disabled = false;
    }
  } },
    field("Usuario", input({ id: "username", name: "username", type: "text", required: true, autofocus: true,
      autocomplete: "username webauthn", autocapitalize: "none", autocorrect: "off", spellcheck: "false" })),
    field("Contraseña", input({ id: "password", name: "password", type: "password", required: true,
      autocomplete: "current-password" })),
    err, btn,
    h("div", { class: "or-sep" }, h("span", { text: "o" })),
    h("button", { class: "btn block", type: "button", onClick: async (e) => {
      err.textContent = "";
      const b = e.currentTarget;
      b.disabled = true;
      stopConditionalPasskey();
      try {
        await loginWithPasskey();
      } catch (ex) {
        if (ex.name !== "NotAllowedError" && ex.name !== "AbortError") err.textContent = ex.message;
      } finally {
        b.disabled = false;
      }
    } }, icon("fingerprint"), "Entrar con llave biométrica"));
  fill($app, h("div", { class: "auth" },
    h("div", { class: "auth-card" }, brand(), h("p", { class: "lead", text: "Accede a tu red privada" }), form,
      isStandalone() ? null : h("div", { style: { textAlign: "center", marginTop: "16px" } },
        h("button", { class: "btn ghost sm", type: "button", onClick: installApp }, icon("download"), "Instalar app")))));
  setTimeout(() => form.querySelector("input").focus(), 30);
  startConditionalPasskey(err);
}

function passwordForm(onDone) {
  const btn = h("button", { class: "btn primary", type: "submit" }, "Actualizar contraseña");
  const form = h("form", { class: "form-grid", onSubmit: async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    if (fd.get("new") !== fd.get("repeat")) return toast("Las contraseñas no coinciden", "err");
    btn.disabled = true;
    try {
      await api("POST", "/api/me/password", { current: fd.get("current"), new: fd.get("new") });
      toast("Contraseña actualizada");
      form.reset();
      onDone && onDone();
    } catch (ex) {
      toast(ex.message, "err");
    } finally {
      btn.disabled = false;
    }
  } },
    // Usuario oculto: el Llavero de iOS / gestores de contraseñas saben así qué entrada actualizar.
    h("input", { type: "text", name: "username", autocomplete: "username", value: state.me ? state.me.username : "",
      readOnly: true, hidden: true, tabIndex: -1, "aria-hidden": "true" }),
    h("div", { class: "full" }, field("Contraseña actual", input({ name: "current", type: "password", required: true, autocomplete: "current-password" }))),
    field("Nueva contraseña", input({ name: "new", type: "password", required: true, minlength: "8", autocomplete: "new-password" }), "Mínimo 8 caracteres"),
    field("Repetir", input({ name: "repeat", type: "password", required: true, minlength: "8", autocomplete: "new-password" })),
    h("div", { class: "full" }, btn));
  return form;
}

function forcePasswordView() {
  fill($app, h("div", { class: "auth" },
    h("div", { class: "auth-card", style: { maxWidth: "520px" } },
      brand(),
      h("p", { class: "lead", text: "Por seguridad, establece una contraseña nueva antes de continuar." }),
      passwordForm(async () => { state.me = await api("GET", "/api/me"); render(); }),
      h("div", { style: { textAlign: "center", marginTop: "14px" } },
        h("button", { class: "btn ghost sm", onClick: logout }, "Cerrar sesión")))));
}

function accountView(main) {
  fill(main,
    pageHead("Cuenta", `Sesión iniciada como ${state.me.username}`),
    passkeysCard(),
    h("div", { class: "card", style: { maxWidth: "720px" } }, h("div", { class: "card-head" }, h("h2", { text: "Cambiar contraseña" })), passwordForm()),
    state.me.role === "tenant" ? h("div", { class: "card", style: { maxWidth: "720px" } },
      h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Dominio personalizado" }),
        h("div", { class: "note", text: "Accede a tu panel con tu propio dominio y HTTPS, por ejemplo vpn.tuempresa.com." }))),
      domainEditor({
        load: () => api("GET", "/api/tenant-domain"),
        save: (domain) => api("PUT", "/api/tenant-domain", { domain }),
        statusUrl: "/api/domain-status",
        example: "vpn.tuempresa.com",
      })) : null,
  );
}

/* ------------------------------------------------------------------ dominios */
function checkLine(ok, okText, badText) {
  return h("div", { class: `check-line ${ok ? "ok" : "bad"}` }, icon(ok ? "check" : "alert"), h("span", { text: ok ? okText : badText }));
}

function domainStatusBlock(st) {
  if (!st || !st.domain) return null;
  const dns = st.dns;
  const expected = dns.expected.join(", ") || "la IP del servidor";
  return h("div", { class: "domain-status" },
    checkLine(dns.ok, `DNS correcto: ${st.domain} → ${dns.resolved.join(", ")}`,
      dns.resolved.length ? `El DNS apunta a ${dns.resolved.join(", ")}; debe apuntar a ${expected}`
        : `${st.domain} todavía no resuelve. Crea el registro A hacia ${expected} (puede tardar unos minutos).`),
    checkLine(st.https.ok, "HTTPS activo con certificado válido",
      `HTTPS pendiente${st.https.error ? `: ${st.https.error}` : ""}`),
    st.https.ok ? h("a", { class: "btn sm", href: `https://${st.domain}`, target: "_blank", rel: "noopener" }, icon("globe"), `Abrir https://${st.domain}`) : null);
}

/* Editor de dominio reutilizable: cuenta del cliente, ficha del cliente (admin). */
function domainEditor({ load, save, statusUrl, example, onChange }) {
  const box = h("div", { class: "grid", style: { gap: "14px" } }, spinnerBlock());
  let data = null;
  let status = null;

  const check = async (btn) => {
    if (btn) { btn.disabled = true; btn.lastChild.textContent = "Comprobando…"; }
    try { status = await api("GET", statusUrl); } catch (e) { toast(e.message, "err"); }
    draw();
  };
  const store = async (value, msg) => {
    try {
      data = await save(value);
      status = null;
      toast(msg);
      onChange && onChange(data);
      draw();
      if (data.domain) check();
    } catch (e) { toast(e.message, "err"); }
  };

  const draw = () => {
    const ip = (data.server_ips || [])[0] || "IP del servidor";
    const inp = input({ placeholder: example, value: data.domain || "", autocapitalize: "off", spellcheck: false, inputmode: "url" });
    const checkBtn = data.domain ? h("button", { class: "btn", onClick: (e) => check(e.currentTarget) }, icon("refresh"), "Comprobar") : null;
    fill(box,
      h("div", { class: "input-group" }, inp,
        h("button", { class: "btn primary", onClick: () => store(inp.value.trim() || null, inp.value.trim() ? "Dominio guardado" : "Dominio eliminado") }, "Guardar")),
      data.domain ? h("div", { class: "cell-flex", style: { flexWrap: "wrap" } },
        h("span", { class: "badge accent" }, icon("globe"), data.domain), checkBtn,
        h("button", { class: "btn ghost sm", onClick: () => store(null, "Dominio eliminado") }, icon("trash"), "Quitar")) : null,
      domainStatusBlock(status),
      h("ol", { class: "steps" },
        h("li", null, "En tu proveedor de dominios crea un registro ", h("b", { text: "A" }), ": ",
          h("code", { text: data.domain || example }), " → ", h("code", { text: ip }), "."),
        h("li", { text: "Escríbelo arriba y pulsa Guardar." }),
        h("li", { text: "Pulsa Comprobar: el certificado HTTPS se emite solo en cuanto el DNS apunta aquí (suele tardar menos de un minuto)." })),
    );
  };

  load().then((d) => { data = d; draw(); if (d.domain) check(); }).catch((e) => fill(box, h("p", { class: "note", text: e.message })));
  return box;
}

/* ------------------------------------------------------------------ copias de seguridad */
async function downloadBackup(name) {
  try {
    const res = await fetch(`/api/admin/backups/${encodeURIComponent(name)}`, { credentials: "same-origin" });
    if (!res.ok) throw new Error(`No se pudo descargar (${res.status})`);
    const file = new File([await res.blob()], name, { type: "application/octet-stream" });
    if ((isIOS() || isStandalone()) && navigator.canShare && navigator.canShare({ files: [file] })) {
      try { await navigator.share({ files: [file], title: name }); return; } catch (ex) { if (ex.name === "AbortError") return; }
    }
    const url = URL.createObjectURL(file);
    const a = h("a", { href: url, download: name, style: { display: "none" } });
    document.body.append(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
  } catch (e) { toast(e.message, "err"); }
}

function backupCard() {
  const card = h("div", { class: "card" }, spinnerBlock());
  let st = null;
  const save = async (patch, msg) => {
    try { st = await api("PUT", "/api/admin/backup", patch); toast(msg); draw(); } catch (e) { toast(e.message, "err"); }
  };
  const passModal = () => formModal({
    title: st.has_passphrase ? "Cambiar frase de paso" : "Frase de paso de las copias",
    fields: [
      passwordField("passphrase", "Frase de paso",
        "Mínimo 12 caracteres. Cifra las copias: sin ella NO se pueden restaurar. Cópiala ahora y guárdala en tu gestor de contraseñas."),
      st.has_passphrase ? h("p", { class: "note full", style: { margin: 0 }, text: "Las copias anteriores seguirán necesitando la frase con la que se hicieron." }) : null,
    ],
    onSubmit: async (fd) => {
      if (fd.get("passphrase").length < 12) throw new Error("Mínimo 12 caracteres");
      st = await api("PUT", "/api/admin/backup", { passphrase: fd.get("passphrase") });
      toast("Frase de paso guardada");
      draw();
    },
  });
  const s3Modal = () => {
    const s3 = st.s3;
    const read = (fd) => ({ s3_endpoint: fd.get("s3_endpoint"), s3_region: fd.get("s3_region"), s3_bucket: fd.get("s3_bucket"),
      s3_prefix: fd.get("s3_prefix"), s3_access_key: fd.get("s3_access_key"), s3_secret_key: fd.get("s3_secret_key") });
    const mono = (props) => input({ class: "input mono", autocapitalize: "off", spellcheck: "false", autocomplete: "off", ...props });
    const testBtn = h("button", { class: "btn", type: "button", onClick: async () => {
      testBtn.disabled = true;
      try { await api("POST", "/api/admin/backup/test-s3", read(new FormData(m.box.querySelector("form")))); toast("Conexión correcta: se puede escribir en el bucket"); }
      catch (e) { toast(e.message, "err"); }
      testBtn.disabled = false;
    } }, icon("refresh"), "Probar conexión");
    const m = formModal({
      title: "Copia externa (S3)",
      fields: [
        h("p", { class: "note full", style: { margin: 0 }, text: "Cualquier almacenamiento compatible con S3: Amazon S3, Cloudflare R2, Backblaze B2, Wasabi, MinIO… Usa una clave con permiso sólo de escritura en ese bucket. Allí las copias no se borran solas: si quieres limitarlas, crea una regla de ciclo de vida en el bucket." }),
        h("div", { class: "full" }, field("Endpoint", mono({ name: "s3_endpoint", required: true, value: s3.endpoint, placeholder: "https://<cuenta>.r2.cloudflarestorage.com", inputmode: "url" }))),
        field("Bucket", mono({ name: "s3_bucket", required: true, value: s3.bucket, placeholder: "copias-vpn" })),
        field("Región", mono({ name: "s3_region", value: s3.region, placeholder: "auto" }), "auto en R2; p. ej. eu-west-1 en AWS."),
        h("div", { class: "full" }, field("Carpeta (prefijo)", mono({ name: "s3_prefix", value: s3.prefix, placeholder: "wireguard-cloud/" }))),
        field("Access key", mono({ name: "s3_access_key", required: true, value: s3.access_key })),
        field("Secret key", mono({ name: "s3_secret_key", type: "password", required: !s3.secret_set, placeholder: s3.secret_set ? "(guardada)" : "" }),
          s3.secret_set ? "Déjalo vacío para conservarla." : null),
        h("div", { class: "full cell-flex", style: { flexWrap: "wrap" } }, testBtn,
          s3.configured ? h("button", { class: "btn ghost", type: "button", onClick: async () => {
            await save({ clear_s3: true }, "Copia externa desactivada"); m.close();
          } }, icon("trash"), "Quitar") : null),
      ],
      onSubmit: async (fd) => { st = await api("PUT", "/api/admin/backup", read(fd)); toast("Copia externa guardada"); draw(); },
    });
  };

  const draw = () => {
    const last = st.last;
    const hours = Array.from({ length: 24 }, (_, i) => h("option", { value: String(i), selected: i === st.hour, text: `${String(i).padStart(2, "0")}:00` }));
    const keeps = [3, 7, 14, 30, 60].map((n) => h("option", { value: String(n), selected: n === st.keep, text: `${n} copias` }));
    if (![3, 7, 14, 30, 60].includes(st.keep)) keeps.push(h("option", { value: String(st.keep), selected: true, text: `${st.keep} copias` }));
    const runBtn = h("button", { class: "btn primary", disabled: !st.has_passphrase, onClick: async () => {
      runBtn.disabled = true;
      runBtn.lastChild.textContent = "Creando…";
      try {
        const r = await api("POST", "/api/admin/backup/run");
        st = r;
        if (r.result.ok) toast(r.result.s3 ? "Copia creada y subida a S3" : "Copia creada");
        else toast(r.result.error, "err");
      } catch (e) { toast(e.message, "err"); }
      draw();
    } }, icon("download"), "Hacer copia ahora");
    fill(card,
      h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Copias de seguridad" }),
        h("div", { class: "note", text: "Copia cifrada de todo: clientes, dispositivos y sus claves, dominios, DNS, servicios y ajustes. Con ella puedes restaurar la plataforma en otro servidor sin que nadie reconfigure nada." }))),
      h("div", { class: "grid", style: { gap: "14px" } },
        st.has_passphrase ? null : h("div", { class: "banner" }, icon("alert"), "Define una frase de paso para empezar a hacer copias."),
        h("div", { class: "cell-flex", style: { flexWrap: "wrap" } },
          runBtn,
          h("button", { class: "btn", onClick: passModal }, icon("key"), st.has_passphrase ? "Cambiar frase de paso" : "Definir frase de paso"),
          h("button", { class: "btn", onClick: s3Modal }, icon("server"), st.s3.configured ? `S3: ${st.s3.bucket}` : "Copia externa (S3)")),
        h("div", { class: "backup-opts" },
          h("label", { class: "switch" },
            h("input", { type: "checkbox", checked: st.enabled, disabled: !st.has_passphrase,
              onChange: (e) => save({ enabled: e.target.checked }, e.target.checked ? "Copias automáticas activadas" : "Copias automáticas desactivadas") }),
            h("span", { class: "track" }), h("span", { text: "Copia automática diaria" })),
          h("label", { class: "inline-field" }, "a las", h("select", { class: "input", onChange: (e) => save({ hour: Number(e.target.value) }, "Hora guardada") }, hours),
            h("span", { class: "note", text: st.timezone })),
          h("label", { class: "inline-field" }, "guardar", h("select", { class: "input", onChange: (e) => save({ keep: Number(e.target.value) }, "Retención guardada") }, keeps))),
        last ? checkLine(last.ok, `Última copia: ${new Date(last.at * 1000).toLocaleString()} · ${fmtBytes(last.size)}${last.s3 ? " · subida a S3" : ""}`,
          `${last.name ? `Última copia: ${fmtDate(last.at)}. ` : ""}${last.error}`) : null,
        st.backups.length ? h("div", { class: "blocked-list" }, st.backups.map((b) => h("div", { class: "blocked-row" },
          h("div", { class: "grow" }, h("div", { class: "mono name", text: b.name }), h("div", { class: "meta", text: `${new Date(b.created_at * 1000).toLocaleString()} · ${fmtBytes(b.size)}` })),
          h("button", { class: "btn ghost icon", title: "Descargar", onClick: () => downloadBackup(b.name) }, icon("download")),
          h("button", { class: "btn ghost icon", title: "Eliminar", onClick: async () => {
            if (!(await confirmDialog({ title: "Eliminar copia", message: `Se borrará ${b.name} de este servidor.`, confirmLabel: "Eliminar" }))) return;
            try { st = await api("DELETE", `/api/admin/backups/${b.name}`); toast("Copia eliminada"); draw(); } catch (e) { toast(e.message, "err"); }
          } }, icon("trash")))))
          : h("p", { class: "note", style: { margin: 0 }, text: "Aún no hay copias en este servidor." }),
        h("div", { class: "help" }, "Restaurar (en el servidor nuevo, tras instalar): ",
          h("code", { text: "sudo wg-manager restore copia.wgpb" }),
          ". Guarda copias fuera del servidor (S3 o descargándolas): si el servidor se pierde, las copias locales también.")),
    );
  };
  api("GET", "/api/admin/backup").then((d) => { st = d; draw(); }).catch((e) => fill(card, h("p", { class: "note", text: e.message })));
  return card;
}

function endpointCard() {
  const card = h("div", { class: "card" }, spinnerBlock());
  const draw = (cfg) => {
    const inp = input({ value: cfg.endpoint, placeholder: cfg.default, class: "input mono", autocapitalize: "off", spellcheck: "false", inputmode: "url" });
    fill(card,
      h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Endpoint de WireGuard" }),
        h("div", { class: "note", text: "La dirección a la que se conectan los dispositivos. Recomendado: un nombre (p. ej. wg.tudominio.com, nube gris en Cloudflare). Así, si cambias de servidor, basta con actualizar el DNS y nadie tiene que reconfigurar nada." }))),
      h("div", { class: "grid", style: { gap: "12px" } },
        h("div", { class: "input-group" }, inp,
          h("button", { class: "btn primary", onClick: async () => {
            try { draw(await api("PUT", "/api/admin/wg-settings", { endpoint: inp.value.trim() || null })); toast("Endpoint guardado"); }
            catch (e) { toast(e.message, "err"); }
          } }, "Guardar")),
        h("div", { class: "help", text: `En uso: ${cfg.effective}:${cfg.port}. Vacío = la IP del servidor (${cfg.default}). ` +
          "Los dispositivos existentes deben reimportar su configuración para usar el nuevo endpoint." })));
  };
  api("GET", "/api/admin/wg-settings").then(draw).catch((e) => fill(card, h("p", { class: "note", text: e.message })));
  return card;
}

function dnsSettingsCard() {
  const card = h("div", { class: "card" }, spinnerBlock());
  const draw = (cfg) => {
    const inp = input({ value: cfg.suffixes.join(", "), placeholder: "vpn, lan", class: "input mono", autocapitalize: "off", spellcheck: false });
    fill(card,
      h("div", { class: "card-head" }, h("div", null, h("h2", { text: "DNS de la red" }),
        h("div", { class: "note", text: "Sufijos de búsqueda que reciben todos los dispositivos (como «vpn, lan» en MikroTik). Con ellos, «nas» se resuelve como «nas.vpn»." }))),
      h("div", { class: "grid", style: { gap: "12px" } },
        h("div", { class: "input-group" }, inp,
          h("button", { class: "btn primary", onClick: async () => {
            try {
              draw(await api("PUT", "/api/admin/dns-settings", { suffixes: inp.value.split(/[\s,]+/).filter(Boolean) }));
              toast("Sufijos guardados");
            } catch (e) { toast(e.message, "err"); }
          } }, "Guardar")),
        h("div", { class: "help", text: `Configuración de los dispositivos: DNS = ${[cfg.server, ...cfg.suffixes].join(", ")}. Máximo 5. ` +
          "Evita «local» (iPhone y Mac lo reservan para mDNS). Los dispositivos existentes deben reimportar su configuración para recibir los cambios." }),
        h("div", { class: "help", text: `Cada cliente gestiona los nombres de su red desde su sección DNS. Reenvío por defecto: ${cfg.upstreams.join(", ")}.` })));
  };
  api("GET", "/api/admin/dns-settings").then(draw).catch((e) => fill(card, h("p", { class: "note", text: e.message })));
  return card;
}

async function settingsView(main) {
  let cfg = await api("GET", "/api/admin/settings");
  let status = null;
  const body = h("div");

  const check = async (btn) => {
    if (btn) { btn.disabled = true; btn.lastChild.textContent = "Comprobando…"; }
    try { status = await api("GET", "/api/domain-status?target=main"); } catch (e) { toast(e.message, "err"); }
    draw();
  };
  const store = async (patch, msg) => {
    try {
      cfg = await api("PUT", "/api/admin/settings", { main_domain: cfg.main_domain, force_https: cfg.force_https, ...patch });
      toast(msg);
      draw();
      if (patch.main_domain !== undefined) { status = null; if (cfg.main_domain) check(); }
    } catch (e) { toast(e.message, "err"); draw(); }
  };

  const draw = () => {
    const ip = cfg.server_ips[0] || "IP del servidor";
    const inp = input({ placeholder: "vpn.tudominio.com", value: cfg.main_domain || "", autocapitalize: "off", spellcheck: false, inputmode: "url" });
    const httpsOk = location.protocol === "https:" || (status && status.https && status.https.ok);
    fill(body,
      h("div", { class: "card" },
        h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Dominio del panel" }),
          h("div", { class: "note", text: "Con un dominio el panel funciona con HTTPS (certificado gratuito de Let's Encrypt, renovado automáticamente) y se puede instalar como app en Android." }))),
        h("div", { class: "grid", style: { gap: "14px" } },
          h("div", { class: "input-group" }, inp,
            h("button", { class: "btn primary", onClick: () => store({ main_domain: inp.value.trim() || null, force_https: inp.value.trim() ? cfg.force_https : false },
              inp.value.trim() ? "Dominio guardado" : "Dominio eliminado") }, "Guardar")),
          cfg.main_domain ? h("div", { class: "cell-flex", style: { flexWrap: "wrap" } },
            h("span", { class: "badge accent" }, icon("globe"), cfg.main_domain),
            h("button", { class: "btn", onClick: (e) => check(e.currentTarget) }, icon("refresh"), "Comprobar")) : null,
          domainStatusBlock(status),
          cfg.main_domain ? h("div", { class: "field" },
            h("label", { class: "switch" },
              h("input", { type: "checkbox", checked: cfg.force_https, disabled: !cfg.force_https && !httpsOk,
                onChange: (e) => store({ force_https: e.target.checked }, e.target.checked ? "HTTPS obligatorio activado" : "HTTPS obligatorio desactivado") }),
              h("span", { class: "track" }), h("span", { text: "Forzar HTTPS" })),
            h("div", { class: "help", text: cfg.force_https
              ? `El acceso por http://IP:puerto redirige a https://${cfg.main_domain}.`
              : "Redirige el acceso por IP y HTTP al dominio seguro. Se habilita cuando la comprobación de HTTPS es correcta." })) : null,
          h("ol", { class: "steps" },
            h("li", null, "En tu proveedor de dominios crea un registro ", h("b", { text: "A" }), ": ",
              h("code", { text: cfg.main_domain || "vpn.tudominio.com" }), " → ", h("code", { text: ip }), "."),
            h("li", { text: "Escríbelo arriba y pulsa Guardar." }),
            h("li", { text: "Pulsa Comprobar. Cuando HTTPS esté activo, abre el panel con el dominio y activa «Forzar HTTPS»." })))),
      endpointCard(),
      backupCard(),
      dnsSettingsCard(),
      h("div", { class: "card" },
        h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Dominios de clientes" }),
          h("div", { class: "note", text: "Cada cliente puede usar su propio dominio (desde su Cuenta o desde su ficha). Allí verá el panel con su nombre y sólo podrá entrar él." }))),
        cfg.tenant_domains.length
          ? h("div", { class: "table-wrap" }, h("table", { class: "cards" },
            h("thead", null, h("tr", null, h("th", { text: "Cliente" }), h("th", { text: "Dominio" }), h("th", { text: "Estado" }))),
            h("tbody", null, cfg.tenant_domains.map((t) => h("tr", { class: "link", onClick: () => go(`#/clients/${t.tenant_id}`) },
              h("td", { class: "primary" }, h("div", { class: "name", text: t.name })),
              h("td", { class: "mono", "data-label": "Dominio", text: t.domain }),
              h("td", { class: "aside" }, h("span", { class: `badge ${t.enabled ? "ok" : "off"}`, text: t.enabled ? "Activo" : "Suspendido" })))))))
          : h("p", { class: "note", text: "Ningún cliente tiene dominio propio todavía." })),
    );
  };

  fill(main, pageHead("Ajustes", "Dominio, HTTPS, DNS de la red y dominios de los clientes"), body);
  draw();
  if (cfg.main_domain) check();
}

/* ------------------------------------------------------------------ admin: panel */
function statCard(ic, label, value, hint, wide = false) {
  return h("div", { class: `card stat${wide ? " wide" : ""}` },
    h("div", { class: "label" }, icon(ic), label),
    h("div", { class: "value", text: value }),
    hint ? h("div", { class: "hint", text: hint }) : null);
}

async function dashboardView(main) {
  const load = async (silent) => {
    const o = await api("GET", "/api/admin/overview");
    const content = h("div", null,
      pageHead("Panel", "Estado de la plataforma WireGuard",
        h("a", { class: "btn primary", href: "#/clients" }, icon("users"), "Gestionar clientes")),
      o.server.interface_up ? null : h("div", { class: "banner" }, icon("alert"),
        `La interfaz ${o.server.interface} no está activa en el servidor. Revisa: systemctl status wg-quick@${o.server.interface}`),
      h("div", { class: "grid stats" },
        statCard("users", "Clientes", String(o.tenants), `${o.tenants_enabled} activos · ${o.tenant_capacity - o.tenants} redes libres`),
        statCard("devices", "Dispositivos", String(o.devices), "en todas las redes"),
        statCard("activity", "En línea", String(o.online), "handshake < 3 min"),
        statCard("arrows", "Tráfico", fmtBytes(o.rx + o.tx), `↓ ${fmtBytes(o.rx)} · ↑ ${fmtBytes(o.tx)}`)),
      h("div", { class: "grid two" },
        h("div", { class: "card" },
          h("div", { class: "card-head" }, h("h2", { text: "Clientes con más tráfico" }), h("a", { href: "#/clients", class: "btn ghost sm" }, "Ver todos")),
          o.top.length ? h("div", { class: "table-wrap" }, h("table", { class: "cards" },
            h("thead", null, h("tr", null, h("th", { text: "Cliente" }), h("th", { text: "Red" }), h("th", { text: "En línea" }), h("th", { text: "Tráfico" }))),
            h("tbody", null, o.top.map((t) => h("tr", { class: "link", onClick: () => go(`#/clients/${t.id}`) },
              h("td", { class: "primary" }, h("div", { class: "name", text: t.name }), h("div", { class: "meta", text: t.username })),
              h("td", { class: "mono", "data-label": "Red", text: t.network }),
              h("td", { "data-label": "En línea" }, `${t.online_count}/${t.device_count}`),
              h("td", { "data-label": "Tráfico", text: fmtBytes(t.rx + t.tx) }))))))
            : h("div", { class: "empty" }, icon("users"), h("h2", { text: "Aún no hay clientes" }),
              h("p", { text: "Crea tu primer cliente para asignarle una red privada." }),
              h("button", { class: "btn primary", onClick: () => newTenantModal(() => render()) }, icon("plus"), "Nuevo cliente"))),
        h("div", { class: "card" },
          h("div", { class: "card-head" }, h("h2", { text: "Servidor" }),
            h("span", { class: `badge ${o.server.interface_up ? "ok" : "off"}` }, h("span", { class: `dot ${o.server.interface_up ? "on" : "dis"}` }), o.server.interface_up ? "Activo" : "Inactivo")),
          h("dl", { class: "kv" },
            h("dt", { text: "Endpoint" }), h("dd", { class: "mono", text: o.server.endpoint }),
            h("dt", { text: "Interfaz" }), h("dd", { class: "mono", text: `${o.server.interface} · ${o.server.address}` }),
            h("dt", { text: "Subred" }), h("dd", { class: "mono", text: `${o.server.subnet} (/${o.server.tenant_prefix} por cliente)` }),
            h("dt", { text: "Filtrado DNS" }), h("dd", null,
              !o.dns.enabled ? "Desactivado"
                : o.dns.running ? `Activo · ${o.dns.filtering_tenants} clientes con filtros · ${o.dns.blocked_24h} bloqueos (24 h)`
                  : h("span", { style: { color: "var(--danger)" }, text: `Error: ${o.dns.error || "no está en ejecución"}` })),
            h("dt", { text: "Clave pública" }), h("dd", null,
              h("div", { class: "cell-flex" }, h("span", { class: "mono", text: o.server.public_key }),
                h("button", { class: "btn ghost icon", title: "Copiar", onClick: () => copyText(o.server.public_key) }, icon("copy"))))))));
    fill(main, content);
  };
  await load();
  every(load);
}

/* ------------------------------------------------------------------ admin: clientes */
async function clientsView(main) {
  let filter = "";
  let tenants = [];
  const tableBox = h("div");
  const draw = () => {
    const q = filter.toLowerCase();
    const rows = tenants.filter((t) => !q || t.name.toLowerCase().includes(q) || t.username.toLowerCase().includes(q) || t.network.includes(q));
    fill(tableBox, !tenants.length
      ? h("div", { class: "empty" }, icon("users"), h("h2", { text: "Sin clientes" }),
        h("p", { text: "Cada cliente recibe su propia red privada aislada." }),
        h("button", { class: "btn primary", onClick: () => newTenantModal(() => load()) }, icon("plus"), "Nuevo cliente"))
      : h("div", { class: "table-wrap" }, h("table", { class: "cards" },
        h("thead", null, h("tr", null, h("th", { text: "Cliente" }), h("th", { text: "Red" }), h("th", { text: "Dispositivos" }),
          h("th", { class: "hide-sm", text: "En línea" }), h("th", { class: "hide-sm", text: "Tráfico" }), h("th", { text: "Estado" }))),
        h("tbody", null, rows.map((t) => h("tr", { class: "link", onClick: () => go(`#/clients/${t.id}`) },
          h("td", { class: "primary" }, h("div", { class: "cell-flex" }, h("div", { class: "avatar", text: initials(t.name) }),
            h("div", null, h("div", { class: "name", text: t.name }), h("div", { class: "meta", text: t.username })))),
          h("td", { class: "mono", "data-label": "Red", text: t.network }),
          h("td", { "data-label": "Dispositivos" }, h("div", { class: "meta", text: `${t.device_count} / ${t.max_devices}` }),
            h("div", { class: "progress" }, h("span", { style: { width: `${Math.min(100, (100 * t.device_count) / t.max_devices)}%` } }))),
          h("td", { class: "hide-sm", "data-label": "En línea" }, h("div", { class: "cell-flex" }, h("span", { class: `dot ${t.online_count ? "on" : ""}` }), String(t.online_count))),
          h("td", { class: "hide-sm", "data-label": "Tráfico", text: fmtBytes(t.rx + t.tx) }),
          h("td", { class: "aside" }, h("span", { class: `badge ${t.enabled ? "ok" : "off"}`, text: t.enabled ? "Activo" : "Suspendido" })))))))
    );
  };
  const load = async () => { tenants = await api("GET", "/api/admin/tenants"); draw(); };
  await load();
  fill(main,
    pageHead("Clientes", "Cada cliente tiene su red /24 privada; sus dispositivos se ven entre sí, pero nunca con los de otros clientes.",
      [h("div", { class: "search" }, icon("search"), input({ placeholder: "Buscar cliente o red…", onInput: (e) => { filter = e.target.value; draw(); } })),
        h("button", { class: "btn primary", onClick: () => newTenantModal(() => load()) }, icon("plus"), "Nuevo cliente")]),
    h("div", { class: "card" }, tableBox));
  every(load);
}

function newTenantModal(onDone) {
  const nameInp = input({ name: "name", required: true, maxlength: "64", placeholder: "Acme S.L." });
  const userInp = input({ name: "username", required: true, pattern: "[A-Za-z0-9][A-Za-z0-9._\\-]{2,31}", placeholder: "acme" });
  let userTouched = false;
  userInp.addEventListener("input", () => { userTouched = true; });
  nameInp.addEventListener("input", () => { if (!userTouched) userInp.value = slugify(nameInp.value); });
  formModal({
    title: "Nuevo cliente",
    submitLabel: "Crear cliente",
    fields: [
      h("div", { class: "full" }, field("Nombre", nameInp)),
      field("Usuario de acceso", userInp, "3-32 caracteres: letras, números . _ -"),
      field("Máx. dispositivos", input({ name: "max_devices", type: "number", min: "1", max: "253", value: "10", required: true })),
      passwordField("password", "Contraseña inicial", "El cliente deberá cambiarla en su primer acceso."),
      h("div", { class: "full" }, field("Notas", h("textarea", { class: "input", name: "notes", maxlength: "500", placeholder: "Plan, contacto, referencia…" }))),
    ],
    onSubmit: async (fd) => {
      const t = await api("POST", "/api/admin/tenants", {
        name: fd.get("name"), username: fd.get("username"), password: fd.get("password"),
        max_devices: Number(fd.get("max_devices")), notes: fd.get("notes") || "",
      });
      toast(`Cliente creado con la red ${t.network}`);
      credentialsModal(t.name, t.username, fd.get("password"), t.network);
      onDone && onDone(t);
    },
  });
}

function credentialsModal(name, username, password, network) {
  const text = `Panel: ${location.origin}\nUsuario: ${username}\nContraseña: ${password}\nRed privada: ${network}`;
  const m = modal({
    title: `Acceso de ${name}`,
    body: [h("p", { class: "note", text: "Comparte estos datos con el cliente. La contraseña no se volverá a mostrar." }), h("pre", { class: "conf", text })],
    actions: [h("button", { class: "btn", onClick: () => copyText(text) }, icon("copy"), "Copiar"),
      h("button", { class: "btn primary", onClick: () => m.close() }, "Hecho")],
  });
}

async function clientDetailView(main, id) {
  const load = async () => {
    const [t, devices] = await Promise.all([api("GET", `/api/admin/tenants/${id}`), api("GET", `/api/devices?tenant_id=${id}`)]);
    const reload = () => load();
    fill(main, 
      pageHead(t.name, h("span", { class: "cell-flex" },
        h("span", { class: `badge ${t.enabled ? "ok" : "off"}`, text: t.enabled ? "Activo" : "Suspendido" }),
        h("span", { class: "mono", text: t.network }),
        t.must_change ? h("span", { class: "badge warn", text: "Pendiente de primer acceso" }) : null,
        filterBadges(t.filters)),
      [
        h("a", { class: "btn", href: `#/clients/${t.id}/filters` }, icon("shield"), "Filtros"),
        h("a", { class: "btn", href: `#/clients/${t.id}/dns` }, icon("server"), "DNS"),
        h("a", { class: "btn", href: `#/clients/${t.id}/services` }, icon("globe"), "Servicios"),
        h("button", { class: "btn", onClick: () => {
          const m = modal({ title: `Dominio de ${t.name}`, wide: true,
            body: domainEditor({
              load: () => api("GET", `/api/tenant-domain?tenant_id=${t.id}`),
              save: (domain) => api("PUT", `/api/tenant-domain?tenant_id=${t.id}`, { domain }),
              statusUrl: `/api/domain-status?tenant_id=${t.id}`,
              example: "vpn.cliente.com",
            }),
            actions: [h("button", { class: "btn", onClick: () => m.close() }, "Cerrar")],
            onClose: reload });
        } }, icon("globe"), "Dominio"),
        h("button", { class: "btn", onClick: () => editTenantModal(t, reload) }, icon("edit"), "Editar"),
        h("button", { class: "btn", onClick: () => resetTenantPassword(t, reload) }, icon("key"), "Contraseña"),
        h("button", { class: `btn ${t.enabled ? "danger" : ""}`, onClick: async () => {
          if (t.enabled && !(await confirmDialog({ title: "Suspender cliente", message: `Se desconectarán todos los dispositivos de ${t.name} y no podrá entrar al panel.`, confirmLabel: "Suspender" }))) return;
          try { await api("PATCH", `/api/admin/tenants/${t.id}`, { enabled: !t.enabled }); toast(t.enabled ? "Cliente suspendido" : "Cliente reactivado"); reload(); } catch (e) { toast(e.message, "err"); }
        } }, icon("power"), t.enabled ? "Suspender" : "Reactivar"),
        h("button", { class: "btn ghost icon", title: "Eliminar cliente", onClick: async () => {
          if (!(await confirmDialog({ title: "Eliminar cliente", message: `Se eliminarán ${t.name}, sus ${t.device_count} dispositivos y su red ${t.network}. Esta acción no se puede deshacer.`, confirmLabel: "Eliminar" }))) return;
          try { await api("DELETE", `/api/admin/tenants/${t.id}`); toast("Cliente eliminado"); go("#/clients"); } catch (e) { toast(e.message, "err"); }
        } }, icon("trash")),
      ],
      [h("a", { href: "#/clients", text: "Clientes" }), " / ", t.name]),
      h("div", { class: "grid stats" },
        statCard("network", "Red privada", t.network, `${t.device_count} de ${t.max_devices} dispositivos`, true),
        statCard("activity", "En línea", String(t.online_count), "dispositivos conectados"),
        statCard("arrows", "Tráfico", fmtBytes(t.rx + t.tx), `↓ ${fmtBytes(t.rx)} · ↑ ${fmtBytes(t.tx)}`),
        statCard("users", "Usuario", t.username, `Alta: ${fmtDate(t.created_at)}`, true)),
      t.notes ? h("div", { class: "card" }, h("h3", { text: "Notas" }), h("p", { style: { margin: "8px 0 0", whiteSpace: "pre-wrap" }, text: t.notes })) : null,
      devicesCard(devices, { tenantId: t.id, max: t.max_devices, onChange: reload }),
    );
  };
  await load();
  every(load);
}

function editTenantModal(t, onDone) {
  formModal({
    title: "Editar cliente",
    fields: [
      h("div", { class: "full" }, field("Nombre", input({ name: "name", required: true, maxlength: "64", value: t.name }))),
      field("Máx. dispositivos", input({ name: "max_devices", type: "number", min: String(Math.max(1, t.device_count)), max: "253", value: String(t.max_devices), required: true })),
      field("Red", input({ value: t.network, disabled: true })),
      h("div", { class: "full" }, field("Notas", h("textarea", { class: "input", name: "notes", maxlength: "500", value: t.notes }))),
    ],
    onSubmit: async (fd) => {
      await api("PATCH", `/api/admin/tenants/${t.id}`, { name: fd.get("name"), max_devices: Number(fd.get("max_devices")), notes: fd.get("notes") || "" });
      toast("Cliente actualizado");
      onDone();
    },
  });
}

function resetTenantPassword(t, onDone) {
  formModal({
    title: `Nueva contraseña para ${t.name}`,
    submitLabel: "Restablecer",
    fields: [passwordField("password", "Contraseña temporal", "Se cerrarán sus sesiones y deberá cambiarla al entrar.")],
    onSubmit: async (fd) => {
      await api("PATCH", `/api/admin/tenants/${t.id}`, { password: fd.get("password") });
      credentialsModal(t.name, t.username, fd.get("password"), t.network);
      onDone();
    },
  });
}

/* ------------------------------------------------------------------ dispositivos (común) */
function devicesCard(devices, { tenantId, max, onChange }) {
  const full = devices.length >= max;
  return h("div", { class: "card" },
    h("div", { class: "card-head" },
      h("div", null, h("h2", { text: "Dispositivos" }), h("div", { class: "note", text: `${devices.length} de ${max} usados` })),
      h("button", { class: "btn primary", disabled: full, title: full ? "Límite alcanzado" : null, onClick: () => newDeviceModal(tenantId, onChange) },
        icon("plus"), "Añadir dispositivo")),
    devices.length
      ? h("div", { class: "table-wrap" }, h("table", { class: "cards" },
        h("thead", null, h("tr", null, h("th", { text: "Dispositivo" }), h("th", { text: "IP" }), h("th", { class: "hide-sm", text: "Último contacto" }),
          h("th", { class: "hide-sm", text: "Tráfico" }), h("th", { class: "hide-sm", text: "Modo" }), h("th"))),
        h("tbody", null, devices.map((d) => deviceRow(d, onChange)))))
      : h("div", { class: "empty" }, icon("devices"), h("h2", { text: "Sin dispositivos" }),
        h("p", { text: "Añade un portátil, móvil o servidor y escanea el QR con la app de WireGuard." })));
}

function deviceRow(d, onChange) {
  const status = !d.enabled ? ["dis", "Deshabilitado"] : d.online ? ["on", "En línea"] : ["", "Desconectado"];
  return h("tr", null,
    h("td", { class: "primary" }, h("div", { class: "cell-flex" }, h("span", { class: `dot ${status[0]}`, title: status[1] }),
      h("div", null, h("div", { class: "name", text: d.name }),
        h("div", { class: "meta", text: [d.endpoint ? `${status[1]} · ${d.endpoint}` : status[1], d.dns_filter ? null : "sin filtros"].filter(Boolean).join(" · ") })))),
    h("td", { class: "mono", "data-label": "IP", text: d.ip }),
    h("td", { class: "hide-sm", "data-label": "Último contacto", text: ago(d.last_handshake) }),
    h("td", { class: "hide-sm", "data-label": "Tráfico", text: `↓ ${fmtBytes(d.tx)} · ↑ ${fmtBytes(d.rx)}` }),
    h("td", { class: "hide-sm", "data-label": "Modo" }, d.kind === "router"
      ? h("span", { class: "badge accent", title: d.lan_networks.join(", ") }, icon("router"), `Router · ${d.lan_networks.join(", ")}`)
      : h("span", { class: `badge ${d.full_tunnel ? "accent" : ""}` }, icon(d.full_tunnel ? "globe" : "network"), d.full_tunnel ? "Todo el tráfico" : "Solo red privada")),
    h("td", { class: "actions aside" },
      h("button", { class: "btn ghost icon", title: "Configuración y QR", onClick: () => deviceConfigModal(d) }, icon("qr")),
      h("button", { class: "btn ghost icon", title: "Editar", onClick: () => editDeviceModal(d, onChange) }, icon("edit")),
      h("button", { class: "btn ghost icon", title: d.enabled ? "Deshabilitar" : "Habilitar", onClick: async () => {
        try { await api("PATCH", `/api/devices/${d.id}`, { enabled: !d.enabled }); toast(d.enabled ? "Dispositivo deshabilitado" : "Dispositivo habilitado"); onChange(); } catch (e) { toast(e.message, "err"); }
      } }, icon("power")),
      h("button", { class: "btn ghost icon", title: "Eliminar", onClick: async () => {
        if (!(await confirmDialog({ title: "Eliminar dispositivo", message: `${d.name} (${d.ip}) perderá el acceso inmediatamente.`, confirmLabel: "Eliminar" }))) return;
        try { await api("DELETE", `/api/devices/${d.id}`); toast("Dispositivo eliminado"); onChange(); } catch (e) { toast(e.message, "err"); }
      } }, icon("trash"))));
}

function tunnelField(checked) {
  return h("div", { class: "full field" },
    switchEl("full_tunnel", checked, "Enviar todo el tráfico por la VPN"),
    h("div", { class: "help", text: "Activado: navega por Internet con la IP del servidor. Desactivado: solo accede a la red privada del cliente." }));
}

function lanField(value) {
  return h("div", { class: "full" }, field("Redes de la LAN del router",
    input({ name: "lan_networks", required: true, value: value || "", placeholder: "192.168.88.0/24", class: "input mono",
      autocapitalize: "off", spellcheck: "false" }),
    "La red (o redes, separadas por comas) que hay detrás del router. Debe ser única en la plataforma: si es 192.168.1.0/24 o similar, mejor cámbiala por una menos común (p. ej. 192.168.123.0/24)."));
}
function splitList(text) { return String(text || "").split(/[\s,;]+/).filter(Boolean); }

function newDeviceModal(tenantId, onDone) {
  const tunnel = tunnelField(true);
  const lan = lanField("");
  lan.hidden = true;
  lan.querySelector("input").required = false;
  const kindSel = h("div", { class: "segmented full" },
    ["device", "router"].map((k) => h("label", null,
      h("input", { type: "radio", name: "kind", value: k, checked: k === "device", onChange: () => {
        const router = k === "router";
        tunnel.hidden = router;
        lan.hidden = !router;
        lan.querySelector("input").required = router;
      } }),
      h("span", null, icon(k === "router" ? "router" : "devices"), k === "router" ? "Router (red completa)" : "Dispositivo"))));
  formModal({
    title: "Añadir dispositivo",
    submitLabel: "Crear",
    fields: [
      kindSel,
      h("div", { class: "full" }, field("Nombre", input({ name: "name", required: true, maxlength: "48", placeholder: "Portátil de Ana, iPhone, MikroTik oficina…" }))),
      tunnel,
      lan,
    ],
    onSubmit: async (fd) => {
      const router = fd.get("kind") === "router";
      const body = router
        ? { name: fd.get("name"), kind: "router", lan_networks: splitList(fd.get("lan_networks")), full_tunnel: false }
        : { name: fd.get("name"), full_tunnel: fd.get("full_tunnel") === "on" };
      if (state.me.role === "admin") body.tenant_id = tenantId;
      const d = await api("POST", "/api/devices", body);
      onDone();
      deviceConfigModal(d, true);
    },
  });
}

function editDeviceModal(d, onDone) {
  formModal({
    title: "Editar dispositivo",
    fields: [
      h("div", { class: "full" }, field("Nombre", input({ name: "name", required: true, maxlength: "48", value: d.name }))),
      h("div", { class: "full" }, field("Nombre de red (DNS)",
        input({ name: "hostname", required: true, maxlength: "63", value: d.hostname || "", pattern: "[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?",
          autocapitalize: "off", spellcheck: false, class: "input mono" }),
        "Los demás dispositivos del cliente lo encuentran por este nombre (p. ej. portatil-ana o portatil-ana.vpn).")),
      d.kind === "router" ? lanField(d.lan_networks.join(", ")) : tunnelField(d.full_tunnel),
      h("div", { class: "full field" },
        switchEl("dns_filter", d.dns_filter, "Aplicar los filtros de navegación"),
        h("div", { class: "help", text: "Desactívalo para que este dispositivo (p. ej. el de un adulto) navegue sin los filtros del cliente." })),
      h("p", { class: "note full", style: { margin: 0 }, text: "Si cambias el modo de túnel, vuelve a importar la configuración en el dispositivo." }),
    ],
    onSubmit: async (fd) => {
      await api("PATCH", `/api/devices/${d.id}`, {
        name: fd.get("name"), dns_filter: fd.get("dns_filter") === "on", hostname: fd.get("hostname"),
        ...(d.kind === "router" ? { lan_networks: splitList(fd.get("lan_networks")) } : { full_tunnel: fd.get("full_tunnel") === "on" }),
      });
      toast("Dispositivo actualizado");
      onDone();
    },
  });
}

/* Guarda el .conf sin abandonar la app. En iOS (sobre todo instalada como PWA)
   un enlace de descarga sustituye la app por una vista previa sin botón de
   volver; por eso allí se usa la hoja de compartir del sistema, que ofrece
   «WireGuard» directamente. En el resto, descarga generada en memoria. */
async function saveConfig(d, conf, ext = "conf") {
  const name = `${d.name.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^A-Za-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 15) || `wg${d.id}`}.${ext}`;
  const file = new File([conf], name, { type: "text/plain" });
  if ((isIOS() || isStandalone()) && navigator.canShare && navigator.canShare({ files: [file] })) {
    try {
      await navigator.share({ files: [file], title: name }); // llamada directa desde el clic (gesto del usuario)
      return;
    } catch (ex) {
      if (ex.name === "AbortError") return; // el usuario cerró la hoja de compartir
    }
  }
  const url = URL.createObjectURL(file);
  const a = h("a", { href: url, download: name, style: { display: "none" } });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function routerConfigModal(d, fresh) {
  let conf = "";
  let rsc = "";
  try {
    [conf, rsc] = await Promise.all([api("GET", `/api/devices/${d.id}/config`), api("GET", `/api/devices/${d.id}/mikrotik`)]);
  } catch (e) { return toast(e.message, "err"); }
  const tabs = [["mikrotik", "MikroTik (RouterOS 7)", rsc], ["conf", "Linux / OpenWrt (.conf)", conf]];
  const pre = h("pre", { class: "conf", text: rsc });
  let current = "mikrotik";
  const tabBar = h("div", { class: "segmented" }, tabs.map(([key, label, text]) => h("label", null,
    h("input", { type: "radio", name: "cfgtab", checked: key === current, onChange: () => { current = key; pre.textContent = text; } }),
    h("span", { text: label }))));
  const m = modal({
    title: fresh ? `${d.name} listo` : d.name,
    wide: true,
    body: [
      h("dl", { class: "kv" },
        h("dt", { text: "IP en la VPN" }), h("dd", { class: "mono", text: d.ip }),
        h("dt", { text: "LAN publicada" }), h("dd", { class: "mono", text: d.lan_networks.join(", ") }),
        h("dt", { text: "Cliente" }), h("dd", { text: d.tenant_name })),
      h("p", { class: "note", style: { margin: 0 } },
        "Copia el script y pégalo en el Terminal del router (Winbox › New Terminal o SSH). Después, los dispositivos de este cliente llegarán a su LAN y la LAN a ellos. ",
        "El tráfico de Internet de la LAN sigue saliendo por su propia conexión."),
      tabBar,
      pre,
      h("div", { class: "cell-flex", style: { flexWrap: "wrap" } },
        h("button", { class: "btn primary", onClick: () => copyText(current === "mikrotik" ? rsc : conf, "Configuración copiada") }, icon("copy"), "Copiar"),
        h("button", { class: "btn", onClick: () => (current === "mikrotik" ? saveConfig(d, rsc, "rsc") : saveConfig(d, conf)) }, icon("download"), "Guardar archivo")),
      h("p", { class: "note", style: { margin: 0 } }, icon("shield"), " Contiene la clave privada del router: no la compartas."),
    ],
    actions: [h("button", { class: "btn", onClick: () => m.close() }, "Cerrar")],
  });
  m.box.querySelectorAll(".note > svg").forEach((svg) => Object.assign(svg.style, { width: "14px", height: "14px", verticalAlign: "-2px" }));
}

async function deviceConfigModal(d, fresh = false) {
  if (d.kind === "router") return routerConfigModal(d, fresh);
  let conf = "";
  try { conf = await api("GET", `/api/devices/${d.id}/config`); } catch (e) { return toast(e.message, "err"); }
  const pre = h("pre", { class: "conf", text: conf, hidden: true });
  const m = modal({
    title: fresh ? `${d.name} listo` : d.name,
    wide: true,
    body: [
      h("div", { class: "qr-layout" },
        h("div", { class: "qr-box" }, h("img", { src: `/api/devices/${d.id}/qr.svg?ts=${Date.now()}`, alt: `QR de ${d.name}` })),
        h("div", { class: "grid", style: { gap: "12px" } },
          h("dl", { class: "kv" },
            h("dt", { text: "IP" }), h("dd", { class: "mono", text: d.ip }),
            h("dt", { text: "Modo" }), h("dd", { text: d.full_tunnel ? "Todo el tráfico" : "Solo red privada" }),
            h("dt", { text: "Cliente" }), h("dd", { text: d.tenant_name })),
          h("ol", { class: "note", style: { margin: 0, paddingLeft: "18px" } },
            h("li", { text: "Instala la app oficial de WireGuard." }),
            h("li", { text: "Móvil: «Añadir túnel» → «Escanear QR»." }),
            h("li", { text: isIOS() ? "En este iPhone/iPad: «Abrir en WireGuard» y elige WireGuard." : "Ordenador: descarga el .conf e impórtalo." })),
          h("div", { class: "cell-flex", style: { flexWrap: "wrap" } },
            h("button", { class: "btn primary", onClick: () => saveConfig(d, conf) },
              icon(isIOS() ? "share" : "download"), isIOS() ? "Abrir en WireGuard" : "Descargar .conf"),
            h("button", { class: "btn", onClick: () => copyText(conf) }, icon("copy"), "Copiar"),
            h("button", { class: "btn ghost", onClick: () => { pre.hidden = !pre.hidden; } }, icon("eye"), "Ver")))),
      pre,
      h("p", { class: "note", style: { margin: 0 } }, icon("shield"), " Esta configuración contiene la clave privada del dispositivo: no la compartas."),
    ],
    actions: [h("button", { class: "btn", onClick: () => m.close() }, "Cerrar")],
  });
  m.box.querySelectorAll(".note > svg").forEach((s) => Object.assign(s.style, { width: "14px", height: "14px", verticalAlign: "-2px" }));
}

/* ------------------------------------------------------------------ filtros de navegación */
const FILTER_ICONS = { ads: "ban", security: "bug", adult: "heart", gambling: "dice", safesearch: "search" };
const FILTER_SHORT = { ads: "Anuncios", security: "Malware", adult: "Adultos", gambling: "Apuestas", safesearch: "Búsqueda segura" };
const PRESETS = [
  ["Protección básica", "Anuncios, rastreadores y malware", { ads: true, security: true, adult: false, gambling: false, safesearch: false }],
  ["Familia", "Malware, adultos, apuestas y búsqueda segura", { ads: false, security: true, adult: true, gambling: true, safesearch: true }],
  ["Máxima", "Todos los filtros", { ads: true, security: true, adult: true, gambling: true, safesearch: true }],
  ["Sin filtros", "Navegación sin restricciones", { ads: false, security: false, adult: false, gambling: false, safesearch: false }],
];

function filterBadges(filters) {
  const on = Object.entries(filters || {}).filter(([, v]) => v).map(([k]) => k);
  if (!on.length) return null;
  return h("span", { class: "badge accent" }, icon("shield"), on.map((k) => FILTER_SHORT[k] || k).join(" · "));
}

async function filtersView(main, tenantId) {
  const isAdmin = state.me.role === "admin";
  const qs = isAdmin ? `?tenant_id=${tenantId}` : "";
  const [catalog, initial, devices, tenant] = await Promise.all([
    api("GET", "/api/filters/catalog"),
    api("GET", `/api/filters${qs}`),
    api("GET", `/api/devices${isAdmin ? `?tenant_id=${tenantId}` : ""}`),
    isAdmin ? api("GET", `/api/admin/tenants/${tenantId}`) : Promise.resolve({ name: state.me.name }),
  ]);
  let data = initial;
  const deviceName = Object.fromEntries(devices.map((d) => [d.ip, d.name]));
  const body = h("div");

  const save = async (patch, msg = "Filtros actualizados") => {
    const payload = { ...data.filters, allowlist: data.allowlist, denylist: data.denylist, ...patch };
    try {
      data = await api("PUT", `/api/filters${qs}`, payload);
      toast(msg);
      draw();
    } catch (e) {
      toast(e.message, "err");
      draw();
    }
  };

  const toggleCard = (key, name, description, extra) => {
    const sw = h("input", { type: "checkbox", checked: !!data.filters[key], onChange: (e) => save({ [key]: e.target.checked },
      e.target.checked ? `${name}: activado` : `${name}: desactivado`) });
    return h("label", { class: `card filter-card${data.filters[key] ? " on" : ""}` },
      h("div", { class: "filter-icon" }, icon(FILTER_ICONS[key])),
      h("div", { class: "grow" }, h("div", { class: "name", text: name }), h("div", { class: "note", text: description }),
        extra ? h("div", { class: "meta", text: extra }) : null),
      h("span", { class: "switch" }, sw, h("span", { class: "track" })));
  };

  const listEditor = (key, title, help) => {
    const ta = h("textarea", { class: "input mono", rows: "6", spellcheck: false, placeholder: "ejemplo.com\notro-dominio.net",
      value: data[key].join("\n") });
    return h("div", { class: "field" }, h("label", { text: title }), ta, h("div", { class: "help", text: help }),
      h("div", null, h("button", { class: "btn sm", onClick: () => save({ [key]: ta.value.split(/[\s,]+/).filter(Boolean) }, "Lista guardada") },
        icon("check"), "Guardar")));
  };

  const draw = () => {
    const st = data.stats;
    const pct = st.queries_24h ? Math.round((100 * st.blocked_24h) / st.queries_24h) : 0;
    const resolver = data.resolver;
    fill(body,
      !resolver.enabled ? h("div", { class: "banner" }, icon("alert"), "El filtrado DNS está desactivado en este servidor.")
        : !resolver.running ? h("div", { class: "banner" }, icon("alert"), `El resolver DNS no está activo${resolver.error ? `: ${resolver.error}` : ""}.`) : null,
      h("div", { class: "grid stats" },
        statCard("activity", "Consultas DNS", String(st.queries_24h), "últimas 24 h"),
        statCard("ban", "Bloqueadas", String(st.blocked_24h), `${pct}% de las consultas`),
        statCard("shield", "Filtros activos", String(Object.values(data.filters).filter(Boolean).length), "de 5 disponibles"),
        statCard("devices", "Dispositivos", String(devices.filter((d) => d.dns_filter).length), `con filtros de ${devices.length}`)),
      h("div", { class: "card" },
        h("div", { class: "card-head" }, h("h2", { text: "Perfiles rápidos" })),
        h("div", { class: "presets" }, PRESETS.map(([name, desc, flags]) => {
          const active = Object.entries(flags).every(([k, v]) => !!data.filters[k] === v);
          return h("button", { class: `preset${active ? " on" : ""}`, onClick: () => save(flags, `Perfil «${name}» aplicado`) },
            h("b", { text: name }), h("span", { text: desc }));
        }))),
      h("div", { class: "filter-grid" },
        catalog.categories.map((c) => toggleCard(c.key, c.name, c.description,
          `${c.domains ? `${c.domains.toLocaleString()} dominios` : "Listas pendientes de descarga"} · ${c.sources.join(", ")}`)),
        toggleCard("safesearch", "Búsqueda segura",
          "Fuerza SafeSearch en Google, Bing y DuckDuckGo y el modo restringido de YouTube.", null)),
      h("div", { class: "grid two" },
        h("div", { class: "card" },
          h("div", { class: "card-head" }, h("h2", { text: "Bloqueados recientemente" })),
          st.recent.length
            ? h("div", { class: "blocked-list" }, st.recent.map((r) => h("div", { class: "blocked-row" },
              h("div", { class: "grow" }, h("div", { class: "mono name", text: r.domain }),
                h("div", { class: "meta", text: `${deviceName[r.client] || r.client} · ${ago(r.ts)}` })),
              data.allowlist.includes(r.domain) ? h("span", { class: "badge ok", text: "Permitido" })
                : h("button", { class: "btn sm", title: "Añadir a «Siempre permitir»",
                  onClick: () => save({ allowlist: [...data.allowlist, r.domain] }, `${r.domain} permitido`) }, "Permitir"))))
            : h("div", { class: "empty" }, icon("shield"), h("p", { text: "Aún no se ha bloqueado nada." }))),
        h("div", { class: "card" },
          h("div", { class: "card-head" }, h("h2", { text: "Listas propias" })),
          h("div", { class: "grid", style: { gap: "16px" } },
            listEditor("allowlist", "Siempre permitir", "Un dominio por línea. Incluye sus subdominios. Tiene prioridad sobre todo lo demás."),
            listEditor("denylist", "Siempre bloquear", "Por ejemplo tiktok.com o roblox.com. Se aplica aunque no haya otros filtros activos.")))),
      st.top.length ? h("div", { class: "card" },
        h("div", { class: "card-head" }, h("h2", { text: "Más bloqueados (24 h)" })),
        h("div", { class: "table-wrap" }, h("table", { class: "cards" },
          h("thead", null, h("tr", null, h("th", { text: "Dominio" }), h("th", { text: "Veces" }))),
          h("tbody", null, st.top.map((t) => h("tr", null,
            h("td", { class: "primary mono", text: t.domain }), h("td", { class: "aside", text: String(t.count) }))))))) : null,
      h("p", { class: "note" }, icon("shield"),
        " El filtrado se aplica en el servidor (DNS) a todos los dispositivos del cliente, con las listas de uBlock Origin y AdGuard compatibles con DNS. ",
        "Puedes excluir un dispositivo concreto desde su edición."),
    );
    body.querySelectorAll(".note > svg").forEach((svg) => Object.assign(svg.style, { width: "14px", height: "14px", verticalAlign: "-2px" }));
  };

  const crumbs = isAdmin ? [h("a", { href: "#/clients", text: "Clientes" }), " / ", h("a", { href: `#/clients/${tenantId}`, text: tenant.name }), " / Filtros"] : null;
  fill(main, pageHead("Navegación segura", `Filtros de Internet para todos los dispositivos de ${tenant.name}`, null, crumbs), body);
  draw();
  every(async () => {
    if (document.activeElement && document.activeElement.tagName === "TEXTAREA") return; // no pisar lo que se escribe
    data = await api("GET", `/api/filters${qs}`);
    draw();
  });
}

/* ------------------------------------------------------------------ DNS propio del cliente */
function fqdns(name, suffixes) {
  return suffixes.length ? suffixes.map((sfx) => `${name}.${sfx}`) : [name];
}

async function zoneView(main, tenantId) {
  const isAdmin = state.me.role === "admin";
  const qs = isAdmin ? `?tenant_id=${tenantId}` : "";
  let zone = await api("GET", `/api/dns-zone${qs}`);
  const tenant = isAdmin ? await api("GET", `/api/admin/tenants/${tenantId}`) : { name: state.me.name };
  const body = h("div");

  const run = async (fn, msg) => {
    try { zone = await fn(); toast(msg); draw(); } catch (e) { toast(e.message, "err"); }
  };

  const draw = () => {
    const sfx = zone.suffixes;
    const example = (zone.devices[0] && zone.devices[0].hostname) || "nas";
    const recName = input({ placeholder: "nas", maxlength: "100", autocapitalize: "off", spellcheck: false, class: "input mono" });
    const recIp = input({ placeholder: zone.network.replace(/0\/\d+$/, "50"), maxlength: "15", inputmode: "decimal", class: "input mono" });
    const ups = input({ value: zone.upstreams.join(", "), placeholder: zone.default_upstreams.join(", "), class: "input mono" });
    fill(body,
      zone.resolver.enabled ? null : h("div", { class: "banner" }, icon("alert"), "El DNS del servidor está desactivado (DNS_ENABLED=false)."),
      h("div", { class: "card net-hero" },
        h("div", { class: "grow" },
          h("h3", { text: "Servidor DNS de tu red" }),
          h("div", { class: "big", text: zone.server }),
          h("div", { class: "note", text: "Tus dispositivos lo usan automáticamente. Resuelve los nombres de tu red (que sólo ven tus dispositivos) y reenvía el resto a Internet." })),
        h("div", null, h("h3", { text: "Sufijos de red" }),
          h("div", { class: "cell-flex", style: { flexWrap: "wrap", marginTop: "6px" } },
            sfx.length ? sfx.map((x) => h("span", { class: "badge accent mono", text: `.${x}` })) : h("span", { class: "note", text: "ninguno" })),
          h("div", { class: "note", style: { marginTop: "6px" }, text: `Ej.: ping ${example} o ${fqdns(example, sfx)[0]}` }))),
      h("div", { class: "card" },
        h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Nombres de los dispositivos" }),
          h("div", { class: "note", text: "Se crean solos a partir del nombre de cada dispositivo. Pulsa el lápiz para cambiarlos." }))),
        zone.devices.length ? h("div", { class: "table-wrap" }, h("table", { class: "cards" },
          h("thead", null, h("tr", null, h("th", { text: "Nombre" }), h("th", { text: "IP" }), h("th", { class: "hide-sm", text: "Dispositivo" }), h("th"))),
          h("tbody", null, zone.devices.map((d) => h("tr", null,
            h("td", { class: "primary" }, h("div", null, h("div", { class: "name mono", text: d.hostname }),
              h("div", { class: "meta mono", text: fqdns(d.hostname, sfx).join("  ·  ") }))),
            h("td", { class: "mono", "data-label": "IP", text: d.ip }),
            h("td", { class: "hide-sm", "data-label": "Dispositivo", text: d.name }),
            h("td", { class: "actions aside" }, h("button", { class: "btn ghost icon", title: "Cambiar nombre", onClick: () => formModal({
              title: `Nombre de red de ${d.name}`,
              fields: [h("div", { class: "full" }, field("Nombre", input({ name: "hostname", required: true, maxlength: "63", value: d.hostname,
                class: "input mono", autocapitalize: "off", spellcheck: false }), "Letras, números y guiones."))],
              onSubmit: async (fd) => {
                await api("PATCH", `/api/devices/${d.id}`, { hostname: fd.get("hostname") });
                zone = await api("GET", `/api/dns-zone${qs}`);
                toast("Nombre actualizado");
                draw();
              },
            }) }, icon("edit")))))))) : h("p", { class: "note", text: "Aún no hay dispositivos." })),
      h("div", { class: "grid two" },
        h("div", { class: "card" },
          h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Registros propios" }),
            h("div", { class: "note", text: "Nombres para otros equipos o servicios: NAS, impresoras, servidores de tu oficina…" }))),
          h("form", { class: "input-group", style: { marginBottom: "14px" }, onSubmit: (e) => {
            e.preventDefault();
            run(() => api("POST", `/api/dns-zone/records${qs}`, { name: recName.value, ip: recIp.value }), "Registro añadido");
          } }, recName, recIp, h("button", { class: "btn primary", type: "submit" }, icon("plus"), "Añadir")),
          zone.records.length ? h("div", { class: "blocked-list" }, zone.records.map((r) => h("div", { class: "blocked-row" },
            h("div", { class: "grow" }, h("div", { class: "mono name", text: `${r.name}  →  ${r.ip}` }),
              h("div", { class: "meta mono", text: fqdns(r.name, sfx).join("  ·  ") })),
            h("button", { class: "btn ghost icon", title: "Eliminar", onClick: async () => {
              if (await confirmDialog({ title: "Eliminar registro", message: `${r.name} dejará de resolverse.`, confirmLabel: "Eliminar" })) {
                run(() => api("DELETE", `/api/dns-zone/records/${r.id}`), "Registro eliminado");
              }
            } }, icon("trash")))))
            : h("p", { class: "note", text: "Sin registros propios." })),
        h("div", { class: "card" },
          h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Servidores DNS de reenvío" }),
            h("div", { class: "note", text: "Opcional: dónde se resuelve todo lo que no es de tu red. Puede ser un DNS público o uno de tu propia red." }))),
          h("div", { class: "grid", style: { gap: "12px" } },
            h("div", { class: "input-group" }, ups,
              h("button", { class: "btn primary", onClick: () => run(() => api("PUT", `/api/dns-zone/upstreams${qs}`,
                { upstreams: ups.value.split(/[\s,]+/).filter(Boolean) }), "Servidores de reenvío guardados") }, "Guardar")),
            h("div", { class: "help", text: `Vacío = los del servidor (${zone.default_upstreams.join(", ")}). Máximo 3. Los filtros de navegación se siguen aplicando.` })))),
      h("p", { class: "note" }, icon("shield"),
        " Los nombres de tu red sólo los resuelven tus dispositivos: ningún otro cliente puede verlos. ",
        "Los dispositivos creados antes de activar los sufijos deben volver a importar su configuración (QR) para usar los nombres cortos."),
    );
    body.querySelectorAll(".note > svg").forEach((svg) => Object.assign(svg.style, { width: "14px", height: "14px", verticalAlign: "-2px" }));
  };

  const crumbs = isAdmin ? [h("a", { href: "#/clients", text: "Clientes" }), " / ", h("a", { href: `#/clients/${tenantId}`, text: tenant.name }), " / DNS"] : null;
  fill(main, pageHead("DNS de la red", `Nombres para los dispositivos de ${tenant.name} (${zone.network})`, null, crumbs), body);
  draw();
}

/* ------------------------------------------------------------------ servicios publicados */
function serviceStatusBlock(st) {
  if (!st) return null;
  const el = domainStatusBlock(st);
  el.insertBefore(checkLine(st.target.ok, "El equipo de destino responde", `Sin respuesta del equipo: ${st.target.error}`), el.querySelector(".btn"));
  return el;
}

function serviceModal(ctx, svc, onDone) {
  const isNew = !svc;
  const targets = ctx.devices.filter((d) => d.kind !== "router");
  const listId = "svc-targets";
  const fields = [
    isNew ? h("div", { class: "full" }, field("Nombre público",
      input({ name: "hostname", required: true, maxlength: "253", placeholder: "nas.tuempresa.com", class: "input mono", autocapitalize: "off", spellcheck: "false", inputmode: "url" }),
      `Un nombre de tu dominio. Crea en tu DNS un registro A hacia ${ctx.ip}.`)) : null,
    field("IP del equipo", input({ name: "target_ip", required: true, maxlength: "15", value: svc ? svc.target_ip : "", list: listId,
      placeholder: ctx.networks[0].replace(/0\/\d+$/, "50"), class: "input mono", inputmode: "decimal" }),
    `De tu red (${ctx.networks.join(", ")}).`),
    field("Puerto", input({ name: "target_port", required: true, type: "number", min: "1", max: "65535", value: svc ? svc.target_port : "", placeholder: "5000", inputmode: "numeric" })),
    h("datalist", { id: listId }, targets.map((d) => h("option", { value: d.ip, text: d.name }))),
    h("div", { class: "full" }, field("Protocolo del equipo",
      h("div", { class: "segmented" }, ["http", "https"].map((k) => h("label", null,
        h("input", { type: "radio", name: "scheme", value: k, checked: (svc ? svc.scheme : "http") === k }),
        h("span", { text: k === "http" ? "HTTP" : "HTTPS (certificado propio)" })))),
      "Cómo habla el equipo dentro de tu red. El público siempre entra por HTTPS con certificado válido.")),
    h("div", { class: "full" }, h("h3", { style: { margin: "6px 0 0" }, text: "Contraseña de acceso (opcional)" }),
      h("div", { class: "note", text: svc && svc.protected ? `Protegido con el usuario «${svc.auth_user}». Rellena la contraseña sólo si quieres cambiarla.`
        : "Añade una capa de usuario y contraseña delante del servicio. Recomendado si el equipo no tiene su propio login." })),
    field("Usuario", input({ name: "auth_user", maxlength: "32", value: svc ? svc.auth_user : "", autocomplete: "off", autocapitalize: "off", spellcheck: "false" })),
    field("Contraseña", input({ name: "auth_password", type: "password", minlength: "8", maxlength: "128", autocomplete: "new-password" })),
    svc && svc.protected ? h("div", { class: "full field" }, switchEl("clear_auth", false, "Quitar la contraseña")) : null,
  ];
  formModal({
    title: isNew ? "Publicar servicio" : `Editar ${svc.hostname}`,
    submitLabel: isNew ? "Publicar" : "Guardar",
    fields,
    onSubmit: async (fd) => {
      const body = { target_ip: fd.get("target_ip").trim(), target_port: Number(fd.get("target_port")), scheme: fd.get("scheme") };
      const user = (fd.get("auth_user") || "").trim();
      const pass = fd.get("auth_password") || "";
      if (fd.get("clear_auth") === "on") body.clear_auth = true;
      else if (pass) { body.auth_user = user; body.auth_password = pass; }
      else if (isNew && user) throw new Error("Indica la contraseña del servicio (mínimo 8 caracteres)");
      let res;
      if (isNew) {
        body.hostname = fd.get("hostname").trim();
        if (ctx.isAdmin) body.tenant_id = ctx.tenantId;
        res = await api("POST", "/api/services", body);
        toast("Servicio publicado");
      } else {
        res = await api("PATCH", `/api/services/${svc.id}`, body);
        toast("Servicio actualizado");
      }
      onDone(res, isNew);
    },
  });
}

async function servicesView(main, tenantId) {
  const isAdmin = state.me.role === "admin";
  const qs = isAdmin ? `?tenant_id=${tenantId}` : "";
  const [tenant, initialDevices] = await Promise.all([
    isAdmin ? api("GET", `/api/admin/tenants/${tenantId}`) : Promise.resolve({ name: state.me.name }),
    api("GET", `/api/devices${qs}`)]);
  let data = await api("GET", `/api/services${qs}`);
  const status = {};
  const body = h("div");
  const ctx = () => ({ isAdmin, tenantId, devices: initialDevices, networks: data.networks, ip: data.server_ips[0] || "la IP del servidor" });

  const reload = async () => { data = await api("GET", `/api/services${qs}`); draw(); };
  const check = async (svc) => {
    status[svc.id] = "loading";
    draw();
    try { status[svc.id] = await api("GET", `/api/services/${svc.id}/status`); } catch (e) { delete status[svc.id]; toast(e.message, "err"); }
    draw();
  };
  const run = async (fn, msg) => { try { await fn(); toast(msg); await reload(); } catch (e) { toast(e.message, "err"); } };

  const row = (svc) => h("div", { class: "card service" },
    h("div", { class: "card-head" },
      h("div", { class: "grow" },
        h("div", { class: "cell-flex", style: { flexWrap: "wrap" } },
          h("a", { class: "mono svc-name", href: `https://${svc.hostname}`, target: "_blank", rel: "noopener", text: svc.hostname }),
          h("span", { class: `badge ${svc.enabled ? "ok" : "off"}`, text: svc.enabled ? "Publicado" : "Pausado" }),
          svc.protected ? h("span", { class: "badge accent", title: `Usuario: ${svc.auth_user}` }, icon("key"), "Con contraseña") : null),
        h("div", { class: "meta mono", text: `→ ${svc.scheme}://${svc.target_ip}:${svc.target_port}${svc.target_name ? `  (${svc.target_name})` : ""}` })),
      h("div", { class: "cell-flex" },
        h("button", { class: "btn sm", disabled: status[svc.id] === "loading", onClick: () => check(svc) }, icon("refresh"), status[svc.id] === "loading" ? "Comprobando…" : "Comprobar"),
        h("button", { class: "btn ghost icon", title: "Editar", onClick: () => serviceModal(ctx(), svc, () => { delete status[svc.id]; reload(); }) }, icon("edit")),
        h("button", { class: "btn ghost icon", title: svc.enabled ? "Pausar" : "Publicar", onClick: () =>
          run(() => api("PATCH", `/api/services/${svc.id}`, { enabled: !svc.enabled }), svc.enabled ? "Servicio pausado" : "Servicio publicado") }, icon("power")),
        h("button", { class: "btn ghost icon", title: "Eliminar", onClick: async () => {
          if (await confirmDialog({ title: "Eliminar servicio", message: `${svc.hostname} dejará de estar accesible desde Internet.`, confirmLabel: "Eliminar" })) {
            run(() => api("DELETE", `/api/services/${svc.id}`), "Servicio eliminado");
          }
        } }, icon("trash")))),
    status[svc.id] && status[svc.id] !== "loading" ? serviceStatusBlock(status[svc.id]) : null);

  const draw = () => {
    const ip = data.server_ips[0] || "la IP del servidor";
    fill(body,
      data.enabled ? null : h("div", { class: "banner" }, icon("alert"), "Los servicios publicados necesitan el HTTPS automático del servidor (ENABLE_HTTPS=true)."),
      data.error ? h("div", { class: "banner" }, icon("alert"), data.error) : null,
      data.services.length ? data.services.map(row) : h("div", { class: "card empty" }, icon("globe"),
        h("h2", { text: "Aún no hay servicios publicados" }),
        h("p", { text: "Publica en Internet, con HTTPS y un nombre propio, un equipo de tu red: un NAS, una cámara, Home Assistant, un servidor web…" }),
        data.enabled ? h("button", { class: "btn primary", onClick: () => serviceModal(ctx(), null, (svc) => { reload().then(() => check(svc)); }) }, icon("plus"), "Publicar servicio") : null),
      h("div", { class: "card" }, h("h3", { text: "Cómo funciona" }),
        h("ol", { class: "steps" },
          h("li", null, "En tu proveedor de dominios crea un registro ", h("b", { text: "A" }), " con el nombre del servicio apuntando a ", h("code", { text: ip }), "."),
          h("li", { text: "Pulsa «Publicar servicio» e indica la IP y el puerto del equipo dentro de tu red." }),
          h("li", { text: "El certificado HTTPS se emite solo en cuanto el DNS apunta aquí. Pulsa Comprobar para verlo." })),
        h("p", { class: "note", style: { margin: "10px 0 0" } }, icon("shield"),
          " El servicio queda accesible desde cualquier lugar de Internet: protégelo con contraseña si el equipo no tiene su propio login. ",
          "El resto de tu red sigue siendo privada.")),
    );
    body.querySelectorAll(".note > svg").forEach((svg) => Object.assign(svg.style, { width: "14px", height: "14px", verticalAlign: "-2px" }));
  };

  const crumbs = isAdmin ? [h("a", { href: "#/clients", text: "Clientes" }), " / ", h("a", { href: `#/clients/${tenantId}`, text: tenant.name }), " / Servicios"] : null;
  const addBtn = data.enabled ? h("button", { class: "btn primary", onClick: () => serviceModal(ctx(), null, (svc) => { reload().then(() => check(svc)); }) }, icon("plus"), "Publicar servicio") : null;
  fill(main, pageHead("Servicios publicados", `Equipos de la red de ${tenant.name} accesibles con HTTPS desde Internet`, addBtn, crumbs), body);
  draw();
}

/* ------------------------------------------------------------------ cliente: mi red */
async function tenantHomeView(main) {
  const load = async () => {
    const devices = await api("GET", "/api/devices");
    const me = state.me;
    const online = devices.filter((d) => d.online).length;
    const rx = devices.reduce((a, d) => a + d.rx, 0);
    const tx = devices.reduce((a, d) => a + d.tx, 0);
    fill(main, 
      pageHead(`Hola, ${me.name}`, "Tu red privada WireGuard",
        h("a", { class: "btn", href: "#/filters" }, icon("shield"), "Filtros de navegación")),
      h("div", { class: "card net-hero" },
        h("div", { class: "grow" },
          h("h3", { text: "Tu red" }),
          h("div", { class: "big", text: me.network }),
          h("div", { class: "note", text: "Tus dispositivos se comunican entre sí dentro de esta red. Ningún otro cliente puede verlos." })),
        h("div", null, h("h3", { text: "Dispositivos" }), h("div", { class: "big", text: `${devices.length}/${me.max_devices}` }),
          h("div", { class: "progress", style: { marginTop: "8px" } }, h("span", { style: { width: `${Math.min(100, (100 * devices.length) / me.max_devices)}%` } }))),
        h("div", null, h("h3", { text: "En línea" }), h("div", { class: "big", text: String(online) })),
        h("div", null, h("h3", { text: "Tráfico" }), h("div", { class: "big", text: fmtBytes(rx + tx) }))),
      devicesCard(devices, { tenantId: me.id, max: me.max_devices, onChange: load }),
    );
  };
  await load();
  every(load);
}

/* ------------------------------------------------------------------ llaves biométricas (passkeys) */
function bufToB64u(buf) {
  let bin = "";
  for (const byte of new Uint8Array(buf)) bin += String.fromCharCode(byte);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64uToBuf(text) {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
  return Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0)).buffer;
}
function passkeySupported() {
  return Boolean(window.PublicKeyCredential && window.isSecureContext && navigator.credentials);
}
function bioLabel() {
  const ua = navigator.userAgent;
  if (/iPhone|iPad|iPod/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1)) return "Face ID / Touch ID";
  if (/Macintosh/.test(ua)) return "Touch ID";
  if (/Android/.test(ua)) return "huella o desbloqueo facial";
  if (/Windows/.test(ua)) return "Windows Hello";
  return "biometría";
}
function deviceLabel() {
  const ua = navigator.userAgent;
  const os = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android"
    : /Macintosh/.test(ua) ? (navigator.maxTouchPoints > 1 ? "iPad" : "Mac") : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "Dispositivo";
  const br = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "";
  return br ? `${os} · ${br}` : os;
}
function noPasskeyHelp() {
  const m = modal({
    title: "Llave biométrica no disponible",
    body: h("p", { class: "note", style: { margin: 0, fontSize: "14px" } },
      window.isSecureContext
        ? "Este navegador no admite llaves de acceso (passkeys). Actualízalo o usa Safari, Chrome o Edge."
        : "Por seguridad, la llave biométrica sólo funciona cuando el panel se abre con su dominio y HTTPS. Pide al administrador que configure el dominio en Ajustes."),
    actions: [h("button", { class: "btn primary", onClick: () => m.close() }, "Entendido")],
  });
}

function credentialToJSON(cred) {
  return {
    id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      authenticatorData: bufToB64u(cred.response.authenticatorData),
      signature: bufToB64u(cred.response.signature),
      userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : undefined,
    },
  };
}

/* Autorrelleno de passkeys: al tocar «Usuario», iOS/Android ofrecen «Iniciar
   sesión con passkey» encima del teclado (WebAuthn conditional mediation). */
function stopConditionalPasskey() {
  if (state.passkeyAbort) { state.passkeyAbort.abort(); state.passkeyAbort = null; }
}
async function startConditionalPasskey(errEl) {
  stopConditionalPasskey();
  if (!passkeySupported() || !PublicKeyCredential.isConditionalMediationAvailable) return;
  try {
    if (!(await PublicKeyCredential.isConditionalMediationAvailable())) return;
    const ctrl = new AbortController();
    state.passkeyAbort = ctrl;
    const { state: st, options } = await api("POST", "/api/passkeys/login/options");
    if (ctrl.signal.aborted) return;
    const cred = await navigator.credentials.get({
      mediation: "conditional",
      signal: ctrl.signal,
      publicKey: { ...options, challenge: b64uToBuf(options.challenge), allowCredentials: [] },
    });
    if (state.passkeyAbort === ctrl) state.passkeyAbort = null;
    await api("POST", "/api/passkeys/login/verify", { state: st, credential: credentialToJSON(cred) });
    state.me = await api("GET", "/api/me");
    state.passkeyChecked = true;
    render();
  } catch (ex) {
    // Abortado (el usuario usó la contraseña o el botón) o sin passkeys: nada que hacer.
    if (ex.name !== "AbortError" && ex.name !== "NotAllowedError" && errEl && ex.status) errEl.textContent = ex.message;
  }
}

async function loginWithPasskey() {
  if (!passkeySupported()) return noPasskeyHelp();
  const { state: st, options } = await api("POST", "/api/passkeys/login/options");
  const cred = await navigator.credentials.get({
    publicKey: {
      ...options,
      challenge: b64uToBuf(options.challenge),
      allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
    },
  });
  await api("POST", "/api/passkeys/login/verify", { state: st, credential: credentialToJSON(cred) });
  state.me = await api("GET", "/api/me");
  state.passkeyChecked = true; // acaba de usar una llave: no sugerir
  render();
}

async function registerPasskey(name = deviceLabel()) {
  if (!passkeySupported()) return noPasskeyHelp();
  const { state: st, options } = await api("POST", "/api/passkeys/register/options");
  const cred = await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: b64uToBuf(options.challenge),
      user: { ...options.user, id: b64uToBuf(options.user.id) },
      excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
    },
  }).catch((ex) => {
    if (ex.name === "InvalidStateError") throw new Error("Este dispositivo ya tiene una llave para este panel.");
    throw ex;
  });
  return api("POST", "/api/passkeys/register/verify", {
    state: st,
    name,
    credential: {
      id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        attestationObject: bufToB64u(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : [],
      },
    },
  });
}

const PASSKEY_SNOOZE_DAYS = 30;
function snoozeKey() { return `wgp-passkey-snooze:${state.me.role}:${state.me.id}`; }

async function suggestPasskey() {
  if (!state.me || state.me.must_change || !passkeySupported()) return;
  try {
    const until = Number(localStorage.getItem(snoozeKey()) || 0);
    if (until > Date.now()) return;
  } catch { /* sin almacenamiento: se sugiere igualmente */ }
  try {
    if (PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable
        && !(await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable())) return;
    const info = await api("GET", "/api/passkeys");
    if (!info.available || info.passkeys.some((k) => k.current)) return;
  } catch { return; }
  if (document.querySelector(".overlay")) return; // no interrumpir otro diálogo
  const later = () => {
    try { localStorage.setItem(snoozeKey(), String(Date.now() + PASSKEY_SNOOZE_DAYS * 864e5)); } catch { /* ignorar */ }
  };
  let decided = false;
  const m = modal({
    title: "Entra más rápido y seguro",
    body: h("div", { class: "passkey-hero" },
      h("div", { class: "passkey-icon" }, icon("fingerprint")),
      h("p", { style: { margin: 0 } }, `Activa el inicio de sesión con ${bioLabel()} en este dispositivo. La próxima vez entrarás sin escribir la contraseña.`),
      h("p", { class: "note", style: { margin: 0 } }, "Tu huella o tu cara nunca salen del dispositivo: sólo se guarda una llave pública cifrada.")),
    actions: [
      h("button", { class: "btn", onClick: () => { decided = true; later(); m.close(); } }, "Ahora no"),
      h("button", { class: "btn primary", onClick: async (e) => {
        e.currentTarget.disabled = true;
        try {
          await registerPasskey();
          decided = true;
          m.close();
          toast(`Listo: ya puedes entrar con ${bioLabel()}`);
          if (location.hash === "#/account") render();
        } catch (ex) {
          e.currentTarget.disabled = false;
          if (ex.name !== "NotAllowedError" && ex.name !== "AbortError") toast(ex.message, "err");
        }
      } }, icon("fingerprint"), "Activar"),
    ],
    onClose: () => { if (!decided) later(); },
  });
}

function passkeysCard() {
  const card = h("div", { class: "card", style: { maxWidth: "720px" } }, spinnerBlock());
  const draw = (info) => {
    const addBtn = h("button", { class: "btn primary", onClick: async () => {
      addBtn.disabled = true;
      try {
        draw(await registerPasskey());
        toast("Llave biométrica añadida");
      } catch (ex) {
        if (ex.name !== "NotAllowedError" && ex.name !== "AbortError") toast(ex.message, "err");
      } finally { addBtn.disabled = false; }
    } }, icon("fingerprint"), "Añadir en este dispositivo");
    fill(card,
      h("div", { class: "card-head" },
        h("div", null, h("h2", { text: "Inicio de sesión biométrico" }),
          h("div", { class: "note", text: `Entra con ${bioLabel()} en lugar de la contraseña (passkeys).` })),
        info.available && passkeySupported() && !info.passkeys.some((k) => k.current) ? addBtn : null),
      !info.available || !passkeySupported()
        ? h("div", { class: "banner" }, icon("alert"), window.isSecureContext && info.available
          ? "Este navegador no admite llaves biométricas."
          : "Disponible cuando el panel se abre con su dominio y HTTPS (Ajustes → Dominio del panel).")
        : null,
      info.passkeys.length
        ? h("div", { class: "blocked-list" }, info.passkeys.map((k) => h("div", { class: "blocked-row" },
          h("div", { class: "filter-icon" }, icon("fingerprint")),
          h("div", { class: "grow" },
            h("div", { class: "name" }, k.name, k.current ? h("span", { class: "badge ok", style: { marginLeft: "8px" }, text: "Este dominio" }) : null),
            h("div", { class: "meta", text: `${k.rp_id} · creada ${fmtDate(k.created_at)} · ${k.last_used_at ? `último uso ${ago(k.last_used_at)}` : "sin usar"}` })),
          h("button", { class: "btn ghost icon", title: "Eliminar", onClick: async () => {
            if (!(await confirmDialog({ title: "Eliminar llave", message: `«${k.name}» dejará de servir para entrar. Podrás volver a crearla.`, confirmLabel: "Eliminar" }))) return;
            try { draw(await api("DELETE", `/api/passkeys/${k.id}`)); toast("Llave eliminada"); } catch (ex) { toast(ex.message, "err"); }
          } }, icon("trash")))))
        : h("p", { class: "note", style: { margin: 0 }, text: "Todavía no tienes llaves biométricas." }),
      info.available && passkeySupported() && info.passkeys.some((k) => k.current)
        ? h("div", { style: { marginTop: "12px" } }, h("button", { class: "btn sm", onClick: addBtn.onclick || (() => addBtn.click()) }, icon("plus"), "Añadir otra llave")) : null,
    );
  };
  api("GET", "/api/passkeys").then(draw).catch((e) => fill(card, h("p", { class: "note", text: e.message })));
  return card;
}

/* ------------------------------------------------------------------ PWA y móvil */
// iOS Safari ignora user-scalable=no: se bloquean a mano el pellizco y el zoom
// por gestos. El doble toque lo desactiva touch-action: manipulation (CSS).
for (const type of ["gesturestart", "gesturechange", "gestureend"]) {
  document.addEventListener(type, (e) => e.preventDefault(), { passive: false });
}
document.addEventListener("touchmove", (e) => { if (e.touches.length > 1) e.preventDefault(); }, { passive: false });

function isStandalone() {
  return window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone === true;
}
// Marca la app instalada para los márgenes de la barra de estado (ver style.css).
if (isStandalone()) document.documentElement.classList.add("standalone");

function isIOS() {
  return /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
}

window.addEventListener("beforeinstallprompt", (e) => {
  e.preventDefault(); // se muestra con nuestro botón «Instalar app»
  state.installPrompt = e;
});
window.addEventListener("appinstalled", () => {
  state.installPrompt = null;
  toast("Aplicación instalada");
});

async function installApp() {
  if (state.installPrompt) {
    state.installPrompt.prompt();
    await state.installPrompt.userChoice.catch(() => null);
    state.installPrompt = null;
    return;
  }
  const steps = isIOS()
    ? [h("p", { style: { margin: 0 }, text: "En Safari:" }),
      h("ol", { style: { margin: 0, paddingLeft: "20px", lineHeight: 1.9 } },
        h("li", null, "Toca el botón ", h("b", { text: "Compartir" }), " (el cuadrado con la flecha)."),
        h("li", null, "Elige ", h("b", { text: "Añadir a pantalla de inicio" }), "."),
        h("li", null, "Pulsa ", h("b", { text: "Añadir" }), ": se abrirá a pantalla completa como una app."))]
    : !window.isSecureContext
      ? [h("p", { style: { margin: 0 }, text: "Chrome y Android solo permiten instalar aplicaciones servidas por HTTPS." }),
        h("p", { class: "note", style: { margin: 0 } }, "Configura un dominio para el panel con ", h("code", { text: "PANEL_DOMAIN" }),
          " en /etc/wg-manager.conf y ejecuta ", h("code", { text: "wg-manager update" }), ": se obtendrá un certificado gratuito automáticamente.")]
      : [h("p", { style: { margin: 0 } }, "Abre el menú del navegador (⋮) y elige ", h("b", { text: "Instalar aplicación" }), " o ", h("b", { text: "Añadir a pantalla de inicio" }), ".")];
  const m = modal({ title: "Instalar WireGuard Cloud", body: steps,
    actions: [h("button", { class: "btn primary", onClick: () => m.close() }, "Entendido")] });
}

if ("serviceWorker" in navigator && window.isSecureContext) {
  const hadController = Boolean(navigator.serviceWorker.controller);
  let reloading = false;
  // Nueva versión desplegada: el SW nuevo toma el control y se recarga una vez.
  navigator.serviceWorker.addEventListener("controllerchange", () => {
    if (!hadController || reloading) return;
    reloading = true;
    location.reload();
  });
  window.addEventListener("load", () => navigator.serviceWorker.register("/sw.js").catch(() => {}));
}

/* ------------------------------------------------------------------ arranque */
(async function boot() {
  const [me, br] = await Promise.all([
    fetch("/api/me", { credentials: "same-origin" }).catch(() => null),
    fetch("/api/branding", { credentials: "same-origin" }).catch(() => null),
  ]);
  if (br && br.ok) state.brand = await br.json();
  document.title = state.brand.title;
  state.me = me && me.ok ? await me.json() : null;
  render();
})();

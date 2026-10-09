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
  plug: '<path d="M9 2v6M15 2v6M6 8h12v4a6 6 0 0 1-12 0z"/><path d="M12 18v4"/>',
  bell: '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
  send: '<path d="m22 2-7 20-4-9-9-4z"/><path d="M22 2 11 13"/>',
  mail: '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-10 6L2 7"/>',
  card: '<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20M6 15h4"/>',
  back: '<path d="m15 18-6-6 6-6"/>',
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
/* Avisos emergentes: se cierran solos (los errores tardan más), con la ✕, o deslizándolos. */
function toast(msg, kind = "ok") {
  const box = document.getElementById("toasts");
  const close = () => {
    if (el.dataset.closing) return;
    el.dataset.closing = "1";
    el.classList.add("leaving");
    setTimeout(() => el.remove(), 180);
  };
  const el = h("div", { class: `toast ${kind}`, role: kind === "err" ? "alert" : "status" },
    h("span", { class: "toast-msg" }, msg),
    h("button", { class: "toast-close", type: "button", "aria-label": "Cerrar aviso", onClick: close }, icon("x")));
  let timer = null;
  const arm = () => { clearTimeout(timer); timer = setTimeout(close, kind === "err" ? 9000 : 4500); };
  // Pasar el ratón o tocarlo lo deja quieto mientras lo lees.
  el.addEventListener("mouseenter", () => clearTimeout(timer));
  el.addEventListener("mouseleave", arm);
  let x0 = null;
  let dx = 0;
  el.addEventListener("touchstart", (e) => { x0 = e.touches[0].clientX; dx = 0; clearTimeout(timer); el.style.transition = "none"; }, { passive: true });
  el.addEventListener("touchmove", (e) => {
    if (x0 === null) return;
    dx = e.touches[0].clientX - x0;
    el.style.transform = `translateX(${dx}px)`;
    el.style.opacity = String(Math.max(0.2, 1 - Math.abs(dx) / 220));
  }, { passive: true });
  el.addEventListener("touchend", () => {
    el.style.transition = "";
    if (Math.abs(dx) > 70) { el.style.transform = `translateX(${dx > 0 ? 120 : -120}%)`; el.style.opacity = "0"; setTimeout(() => el.remove(), 180); }
    else { el.style.transform = ""; el.style.opacity = ""; arm(); }
    x0 = null;
  });
  box.append(el);
  while (box.children.length > 4) box.firstChild.remove();
  arm();
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
  overlay.closeModal = close; // al cambiar de página se cierran los diálogos abiertos
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
  const parts = (location.hash.replace(/^#\/?/, "").split("?")[0] || "").split("/").filter(Boolean);
  return parts;
}
function hashParam(name) { return new URLSearchParams(location.hash.split("?")[1] || "").get(name); }
/* Navegación.
   En iPhone/iPad, deslizar desde el borde izquierdo es el «volver» del sistema y
   chocaría con el gesto del menú. Allí las pantallas no se apilan en el historial
   del navegador (se reemplazan) y la app lleva su propia pila para el botón «Atrás»;
   así ese borde queda sólo para el menú. En el resto se usa el historial normal
   (botón atrás de Android y del navegador). */
const IOS_NAV = isIOS();
let navStack = [];
let navBacking = false;
if (IOS_NAV) {
  try { navStack = JSON.parse(sessionStorage.getItem("wgpStack") || "[]"); } catch { navStack = []; }
  if (navStack[navStack.length - 1] !== (location.hash || "#/")) navStack.push(location.hash || "#/");
}
function saveStack() { try { sessionStorage.setItem("wgpStack", JSON.stringify(navStack.slice(-50))); } catch { /* ignorado */ } }
function navigate(hash) {
  if (IOS_NAV) location.replace(hash.startsWith("#") ? hash : `#${hash}`);
  else location.hash = hash;
}
function go(hash) { if (location.hash !== hash) navigate(hash); else render(); }
if (IOS_NAV) {
  // Los enlaces internos (#/...) también reemplazan en lugar de apilar.
  document.addEventListener("click", (e) => {
    const a = e.target.closest && e.target.closest('a[href^="#"]');
    if (!a || a.target || a.hasAttribute("download") || e.defaultPrevented || e.metaKey || e.ctrlKey) return;
    const href = a.getAttribute("href");
    if (href === "#") return;
    e.preventDefault();
    go(href);
  });
}

/* «Atrás»: se numera cada pantalla en history.state para saber si hay una anterior
   dentro de la app (también con los botones atrás/adelante del navegador). */
const navBase = (history.state && history.state.wgpNav) || 1;
function markNav() {
  if (!history.state || !history.state.wgpNav) {
    const prev = Number(sessionStorage.getItem("wgpNavLast") || navBase - 1);
    history.replaceState({ ...(history.state || {}), wgpNav: prev + 1 }, "");
  }
  sessionStorage.setItem("wgpNavLast", String(history.state.wgpNav));
}
try { markNav(); } catch { /* sin sessionStorage: «Atrás» usará la pantalla superior */ }
function parentRoute() {
  const [section, id, sub] = route();
  if (!section || ["invite", "get", "signup"].includes(section)) return null;
  if (section === "clients" && id && sub) return `#/clients/${id}`;
  if (section === "clients" && id) return "#/clients";
  if (section === "plan" && id && state.me && state.me.role === "admin") return `#/clients/${id}`;
  return null;
}
function canGoBack() {
  if (IOS_NAV) return navStack.length > 1 || Boolean(parentRoute());
  return Boolean(parentRoute()) || ((history.state && history.state.wgpNav) || navBase) > navBase;
}
function goBack() {
  if (IOS_NAV) {
    if (navStack.length > 1) {
      navStack.pop();
      navBacking = true;
      saveStack();
      go(navStack[navStack.length - 1]);
    } else if (parentRoute()) {
      navStack = [];
      go(parentRoute());
    }
    return;
  }
  if (((history.state && history.state.wgpNav) || navBase) > navBase) history.back();
  else if (parentRoute()) go(parentRoute());
}
function backButton(extra = "") {
  return canGoBack() ? h("button", { class: `btn ghost back-btn ${extra}`, type: "button", title: "Volver", "aria-label": "Volver", onClick: goBack },
    icon("back"), h("span", { text: "Atrás" })) : null;
}

window.addEventListener("hashchange", () => {
  try { markNav(); } catch { /* ignorado */ }
  if (IOS_NAV) {
    const here = location.hash || "#/";
    if (navBacking) navBacking = false;
    else if (navStack[navStack.length - 1] !== here) navStack.push(here);
    saveStack();
  }
  document.querySelectorAll(".overlay").forEach((o) => (o.closeModal ? o.closeModal() : o.remove()));
  render();
});

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
  // Páginas públicas: invitación de un usuario y enlace de instalación de un dispositivo.
  const [pub, token] = route();
  if (pub === "invite" && token) return inviteView(token);
  if (pub === "get" && token) return sharedConfigView(token);
  if (pub === "signup") return signupView(token);
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
    if (state.me.suspended || section === "plan") return await planView(main, state.me.role === "admin" ? Number(id) : state.me.id);
    if (section === "alerts") return await alertsView(main);
    if (section === "settings" && isAdmin) return await settingsView(main);
    if (section === "server" && isAdmin) return await serverView(main);
    if (section === "billing" && isAdmin) return await billingAdminView(main);
    if (isAdmin) {
      if (section === "clients" && id && sub === "filters") return await filtersView(main, Number(id));
      if (section === "clients" && id && sub === "dns") return await zoneView(main, Number(id));
      if (section === "clients" && id && sub === "services") return await servicesView(main, Number(id));
      if (section === "clients" && id && sub === "ports") return await portsView(main, Number(id));
      if (section === "clients" && id && sub === "activity") return await activityView(main, Number(id));
      if (section === "clients" && id && sub === "users") return await usersView(main, Number(id));
      if (section === "activity") return await activityView(main, null);
      if (section === "clients" && id) return await clientDetailView(main, Number(id));
      if (section === "clients") return await clientsView(main);
      return await dashboardView(main);
    }
    if (section === "activity") return await activityView(main, state.me.tenant_id);
    if (state.me.role === "member") return await memberHomeView(main);
    if (section === "filters") return await filtersView(main, state.me.id);
    if (section === "dns") return await zoneView(main, state.me.id);
    if (section === "services") return await servicesView(main, state.me.id);
    if (section === "ports") return await portsView(main, state.me.id);
    if (section === "users") return await usersView(main, state.me.id);
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
  const links = state.me.suspended
    ? [["plan", "#/plan", "card", "Plan y pago"], ["account", "#/account", "key", "Cuenta"]]
    : state.me.role === "member"
    ? [["home", "#/", "devices", "Mis dispositivos"], ["activity", "#/activity", "activity", "Actividad"],
      ["alerts", "#/alerts", "bell", "Avisos"], ["account", "#/account", "key", "Cuenta"]]
    : isAdmin
    ? [["home", "#/", "dashboard", "Panel"], ["clients", "#/clients", "users", "Clientes"], ["activity", "#/activity", "activity", "Actividad"],
      ["server", "#/server", "server", "Servidor"], ["billing", "#/billing", "card", "Facturación"], ["alerts", "#/alerts", "bell", "Avisos"], ["settings", "#/settings", "globe", "Ajustes"],
      ["account", "#/account", "key", "Cuenta"]]
    : [["home", "#/", "network", "Mi red"], ["activity", "#/activity", "activity", "Actividad"], ["dns", "#/dns", "server", "DNS"], ["services", "#/services", "globe", "Servicios"],
      ["ports", "#/ports", "plug", "Puertos"], ["users", "#/users", "users", "Usuarios"], ["alerts", "#/alerts", "bell", "Avisos"],
      ["plan", "#/plan", "card", "Plan"],
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
      h("div", { class: "who" }, h("b", { text: state.me.name || state.me.username }),
        h("span", { text: isAdmin ? "Administrador" : state.me.role === "member" ? state.me.tenant_name : "Cliente" })),
      h("button", { class: "btn ghost icon", title: "Cerrar sesión", onClick: logout }, icon("logout"))),
  );
  const main = h("main", { class: "main" }, spinnerBlock());
  const backdrop = h("div", { class: "nav-backdrop", onClick: () => setMenu(false) });
  const topbar = h("div", { class: "topbar" },
    h("button", { class: "btn ghost icon", "aria-label": "Menú", onClick: () => setMenu(!sidebar.classList.contains("open")) }, icon("menu")),
    brand(),
    h("span", { class: "grow" }),
    backButton());
  sidebar.querySelectorAll(".nav a").forEach((a) => a.addEventListener("click", () => setMenu(false)));
  clear($app);
  $app.className = "";
  $app.append(h("div", { class: "layout" }, sidebar, backdrop, h("div", null, topbar, main)));
  return main;
}

/* Menú lateral en móvil: botón, toque fuera, o deslizar el dedo desde el borde izquierdo
   (y hacia la izquierda para cerrarlo). */
function setMenu(open) {
  const sb = document.querySelector(".sidebar");
  if (!sb) return;
  sb.style.transform = "";
  sb.classList.toggle("open", open);
  document.body.classList.toggle("menu-open", open);
}
(function menuGestures() {
  const EDGE = 28;
  let start = null;
  let dragging = false;
  const width = () => (document.querySelector(".sidebar") || {}).offsetWidth || 260;
  const mobile = () => window.matchMedia("(max-width: 760px)").matches;
  document.addEventListener("touchstart", (e) => {
    const sb = document.querySelector(".sidebar");
    if (!sb || !mobile() || e.touches.length !== 1 || document.querySelector(".overlay")) return;
    const t = e.touches[0];
    const open = sb.classList.contains("open");
    if ((!open && t.clientX <= EDGE) || (open && t.clientX <= width() + 40)) {
      start = { x: t.clientX, y: t.clientY, open, time: Date.now() };
      dragging = false;
    }
  }, { passive: true });
  document.addEventListener("touchmove", (e) => {
    if (!start) return;
    const t = e.touches[0];
    const dx = t.clientX - start.x;
    const dy = t.clientY - start.y;
    if (!dragging) {
      if (Math.abs(dy) > Math.abs(dx) && Math.abs(dy) > 8) { start = null; return; } // desplazamiento vertical
      if (Math.abs(dx) < 8) return;
      dragging = true;
      document.querySelector(".sidebar").style.transition = "none";
    }
    const w = width();
    const offset = start.open ? Math.min(0, dx) : Math.min(0, -w + dx);
    document.querySelector(".sidebar").style.transform = `translateX(${Math.max(-w, offset)}px)`;
    document.body.classList.add("menu-dragging");
  }, { passive: true });
  document.addEventListener("touchend", (e) => {
    if (!start) return;
    const sb = document.querySelector(".sidebar");
    document.body.classList.remove("menu-dragging");
    if (dragging && sb) {
      sb.style.transition = "";
      const dx = e.changedTouches[0].clientX - start.x;
      const fast = Math.abs(dx) / Math.max(1, Date.now() - start.time) > 0.4;
      setMenu(start.open ? !(dx < -width() / 3 || (fast && dx < 0)) : (dx > width() / 3 || (fast && dx > 0)));
    }
    start = null;
    dragging = false;
  });
})();

function pageHead(title, sub, actions, crumbs) {
  const back = backButton("hide-mobile");
  return h("div", { class: "page-head" },
    h("div", null,
      back || crumbs ? h("div", { class: "crumbs" }, back, crumbs) : null,
      h("h1", { text: title }),
      sub ? h("div", { class: "sub" }, sub) : null),
    actions ? h("div", { class: "cell-flex" }, actions) : null);
}

async function logout() {
  try { await api("POST", "/api/auth/logout"); } catch { /* ignorar */ }
  state.me = null;
  navStack = [];
  go("#/");
}

/* ------------------------------------------------------------------ login */
function loginView() {
  $app.className = "";
  const signupLink = h("p", { class: "note", style: { textAlign: "center", margin: "16px 0 0" } });
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
      signupLink,
      isStandalone() ? null : h("div", { style: { textAlign: "center", marginTop: "16px" } },
        h("button", { class: "btn ghost sm", type: "button", onClick: installApp }, icon("download"), "Instalar app")))));
  fetch("/api/signup").then((r) => r.json()).then((d) => {
    if (d.enabled) fill(signupLink, "¿Aún no tienes cuenta? ", h("a", { href: "#/signup", text: "Crea tu red privada" }));
  }).catch(() => {});
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

/* Restaurar una copia (p. ej. tras instalar en un servidor nuevo). */
function restoreModal() {
  const fileInp = h("input", { type: "file", accept: ".wgpb", class: "input", required: true });
  const passInp = input({ type: "password", autocomplete: "off", placeholder: "Frase de paso de la copia" });
  const result = h("div");
  const err = h("div", { class: "help", style: { color: "var(--danger)" } });
  let passphrase = "";
  const checkBtn = h("button", { class: "btn primary", onClick: async () => {
    err.textContent = "";
    const file = fileInp.files[0];
    if (!file) { err.textContent = "Elige el archivo .wgpb"; return; }
    if (!passInp.value) { err.textContent = "Escribe la frase de paso"; return; }
    checkBtn.disabled = true;
    checkBtn.lastChild.textContent = "Comprobando…";
    try {
      const res = await fetch("/api/admin/backup/upload", { method: "POST", credentials: "same-origin", body: file,
        headers: { "X-WGP": "1", "Content-Type": "application/octet-stream", "X-Passphrase": encodeURIComponent(passInp.value) } });
      const info = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(errorMessage(info, res.status));
      passphrase = passInp.value;
      showInfo(info);
    } catch (e) { err.textContent = e.message; }
    checkBtn.disabled = false;
    checkBtn.lastChild.textContent = "Comprobar";
  } }, icon("check"), "Comprobar");
  const showInfo = (info) => {
    fill(result, h("div", { class: "domain-status" },
      checkLine(true, `Copia del ${new Date(info.created_at * 1000).toLocaleString()} descifrada correctamente`, ""),
      h("dl", { class: "kv" },
        h("dt", { text: "Clientes" }), h("dd", { text: String(info.tenants) }),
        h("dt", { text: "Dispositivos" }), h("dd", { text: String(info.devices) }),
        h("dt", { text: "Endpoint de los dispositivos" }), h("dd", { class: "mono", text: info.device_endpoint || "(IP del servidor anterior)" }),
        h("dt", { text: "Dominio del panel" }), h("dd", { class: "mono", text: info.main_domain || "—" })),
      info.network_ok ? null : checkLine(false, "", info.network_error)),
      info.network_ok ? h("div", { class: "banner warn", style: { marginTop: "12px" } }, icon("alert"),
        "Se reemplazarán TODOS los datos de este panel (clientes, dispositivos, ajustes y cuentas) por los de la copia. Después entrarás con el usuario y la contraseña del servidor anterior.") : null,
      info.network_ok ? h("button", { class: "btn danger", style: { marginTop: "12px" }, onClick: async (e) => {
        const b = e.currentTarget;
        b.disabled = true;
        b.textContent = "Restaurando…";
        try {
          const r = await api("POST", "/api/admin/backup/restore", { passphrase });
          m.close();
          const done = modal({
            title: "Copia restaurada",
            body: [
              checkLine(true, `${r.tenants} clientes y ${r.devices} dispositivos recuperados.`, ""),
              r.warnings.length ? h("ul", { class: "steps" }, r.warnings.map((w) => h("li", { text: w }))) : null,
              h("p", { class: "note", style: { margin: 0 }, text: "Entra ahora con el usuario y la contraseña que usabas en el servidor anterior." }),
            ],
            actions: [h("button", { class: "btn primary", onClick: () => { done.close(); state.me = null; navStack = []; go("#/"); } }, "Iniciar sesión")],
          });
        } catch (ex) { err.textContent = ex.message; b.disabled = false; b.textContent = "Restaurar ahora"; }
      } }, "Restaurar ahora") : null);
  };
  const m = modal({
    title: "Restaurar una copia",
    wide: true,
    body: [
      h("p", { class: "note", style: { marginTop: 0 }, text: "Recupera la plataforma de otro servidor (o de una fecha anterior): elige el archivo .wgpb que descargaste y su frase de paso." }),
      field("Archivo de la copia", fileInp),
      field("Frase de paso", passInp),
      h("div", { class: "cell-flex" }, checkBtn),
      err,
      result,
    ],
    actions: [h("button", { class: "btn", onClick: () => { api("DELETE", "/api/admin/backup/upload").catch(() => {}); m.close(); } }, "Cancelar")],
  });
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
          h("button", { class: "btn", onClick: restoreModal }, icon("refresh"), "Restaurar una copia"),
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

/* Actualizaciones: el panel pide «wg-manager update» al host (wgp-update.path). */
function updatesCard() {
  const card = h("div", { class: "card" }, spinnerBlock());
  const DAYS = [["daily", "Todos los días"], ["0", "Los lunes"], ["1", "Los martes"], ["2", "Los miércoles"],
    ["3", "Los jueves"], ["4", "Los viernes"], ["5", "Los sábados"], ["6", "Los domingos"]];
  const STATES = {
    queued: "Actualización solicitada; el servidor la empezará en unos segundos…",
    running: "Actualizando el servidor… El panel se reiniciará unos segundos; los túneles VPN no se cortan.",
  };
  let st = null, startVersion = null, polling = false, showLog = false;
  const busy = () => ["queued", "running"].includes(st.status.state);

  const poll = async () => {
    if (polling) return;
    polling = true;
    while (card.isConnected) {
      await new Promise((r) => setTimeout(r, 3000));
      try { st = await api("GET", "/api/admin/update"); } catch { continue; }   // el panel se está reiniciando
      if (!busy()) break;
      draw();
    }
    polling = false;
    if (!card.isConnected) return;
    if (st.status.state === "done") {
      toast(st.current && st.current !== startVersion ? `Servidor actualizado a v${st.current}` : "Actualización terminada");
      if (st.current !== startVersion) { setTimeout(() => location.reload(), 1500); return; }
    } else if (st.status.state === "failed") toast("La actualización ha fallado: revisa el registro", "err");
    draw();
  };
  const run = async () => {
    const msg = st.available ? `Se instalará la v${st.latest}.` : "Se reinstalará la versión actual con la última configuración.";
    if (!(await confirmDialog({ title: "Actualizar el servidor",
      message: `${msg} El panel se reiniciará y estará unos segundos sin responder; los túneles VPN no se cortan.`,
      confirmLabel: "Actualizar", danger: false }))) return;
    try {
      startVersion = st.current;
      st = await api("POST", "/api/admin/update/run");
      draw();
      poll();
    } catch (e) { toast(e.message, "err"); }
  };
  const saveAuto = async (patch) => {
    try {
      st.auto = { ...st.auto, ...patch };   // cambios seguidos (día y hora) no se pisan
      st = await api("PUT", "/api/admin/update/auto", st.auto);
      toast(st.auto.enabled ? "Actualización automática guardada" : "Actualización automática desactivada");
    } catch (e) { toast(e.message, "err"); }
    draw();
  };

  const draw = () => {
    const s = st.status;
    const checkBtn = h("button", { class: "btn", disabled: busy(), onClick: async () => {
      checkBtn.disabled = true;
      checkBtn.lastChild.textContent = "Buscando…";
      try {
        st = await api("POST", "/api/admin/update/check");
        if (st.check_error) toast(st.check_error, "err");
        else toast(st.available ? `Hay una versión nueva: v${st.latest}` : "Ya tienes la última versión");
      } catch (e) { toast(e.message, "err"); }
      draw();
    } }, icon("refresh"), "Buscar actualizaciones");
    const runBtn = h("button", { class: `btn ${st.available ? "primary" : ""}`, disabled: !st.ready || busy(), onClick: run },
      icon("download"), busy() ? "Actualizando…" : st.available ? `Actualizar a v${st.latest}` : "Reinstalar");
    const hours = Array.from({ length: 24 }, (_, i) => h("option", { value: String(i), selected: i === st.auto.hour, text: `${String(i).padStart(2, "0")}:00` }));
    const days = DAYS.map(([v, t]) => h("option", { value: v, selected: v === st.auto.day, text: t }));
    const finished = s.finished_at ? new Date(s.finished_at * 1000).toLocaleString() : "";
    fill(card,
      h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Actualizaciones" }),
        h("div", { class: "note", text: "Actualiza el servidor (panel, firewall y script) a la última versión publicada. El panel se reinicia unos segundos; las conexiones VPN siguen activas." }))),
      h("div", { class: "grid", style: { gap: "14px" } },
        st.ready ? null : h("div", { class: "banner" }, icon("alert"),
          h("span", null, "Para actualizar desde aquí, ejecuta una vez en el servidor ", h("code", { text: "sudo wg-manager update" }), ".")),
        h("div", { class: "cell-flex", style: { flexWrap: "wrap" } },
          h("span", { class: "badge accent" }, `Instalada: ${st.current ? `v${st.current}` : "desconocida"}`),
          st.latest ? h("span", { class: `badge ${st.available ? "warn" : "ok"}` }, st.available ? `Disponible: v${st.latest}` : "Al día") : null,
          st.commit ? h("span", { class: "note mono", text: st.commit }) : null,
          st.checked_at ? h("span", { class: "note", text: `Comprobado ${ago(st.checked_at)}` }) : null),
        st.check_error ? checkLine(false, "", st.check_error) : null,
        h("div", { class: "cell-flex", style: { flexWrap: "wrap" } }, runBtn, checkBtn),
        STATES[s.state] ? h("div", { class: "banner" }, h("div", { class: "spinner sm" }), STATES[s.state]) : null,
        s.state === "stuck" ? checkLine(false, "", "El servidor no ha recogido la petición. Comprueba en el servidor: systemctl status wgp-update.path") : null,
        s.state === "lost" ? checkLine(false, "", "La última actualización no terminó. Revisa el registro o ejecuta «sudo wg-manager update» en el servidor.") : null,
        s.state === "done" ? checkLine(true, `Última actualización: ${finished}${s.version ? ` · v${s.version}` : ""}${s.reason === "automática" ? " · automática" : ""}`, "") : null,
        s.state === "failed" ? checkLine(false, "", `La última actualización falló (${finished}, código ${s.exit_code}).`) : null,
        h("div", { class: "backup-opts" },
          h("label", { class: "switch" },
            h("input", { type: "checkbox", checked: st.auto.enabled, disabled: !st.ready, onChange: (e) => saveAuto({ enabled: e.target.checked }) }),
            h("span", { class: "track" }), h("span", { text: "Actualizar automáticamente" })),
          h("label", { class: "inline-field" }, h("select", { class: "input", onChange: (e) => saveAuto({ day: e.target.value }) }, days)),
          h("label", { class: "inline-field" }, "a las", h("select", { class: "input", onChange: (e) => saveAuto({ hour: Number(e.target.value) }) }, hours),
            h("span", { class: "note", text: st.timezone }))),
        h("div", { class: "help", text: st.auto.enabled
          ? "Sólo se actualiza si hay una versión nueva. Recibirás un aviso con el resultado (Avisos, como las copias fallidas)."
          : "Elige un momento con poco uso: durante la actualización el panel no responde unos segundos." }),
        st.log ? h("div", null,
          h("button", { class: "btn ghost", onClick: () => { showLog = !showLog; draw(); } }, icon("server"), showLog ? "Ocultar registro" : "Ver registro de la última actualización"),
          showLog ? h("pre", { class: "conf", style: { marginTop: "10px", maxHeight: "360px" }, text: st.log }) : null) : null),
    );
    if (showLog) { const pre = card.querySelector("pre"); if (pre) pre.scrollTop = pre.scrollHeight; }
  };
  api("GET", "/api/admin/update").then((d) => {
    st = d;
    startVersion = d.current;
    draw();
    if (busy()) poll();
  }).catch((e) => fill(card, h("p", { class: "note", text: e.message })));
  return card;
}

/* Página pública: presentación del servicio y planes en un dominio propio. */
function siteCard() {
  const card = h("div", { class: "card" }, spinnerBlock());
  let cfg = null;
  let status = null;
  const check = async () => {
    try { status = await api("GET", "/api/admin/site/status"); } catch (e) { toast(e.message, "err"); }
    draw();
  };
  const save = async (patch, msg) => {
    try { cfg = await api("PUT", "/api/admin/site", patch); toast(msg); status = null; draw(); if (cfg.domains.length) check(); }
    catch (e) { toast(e.message, "err"); }
  };
  const editTexts = () => formModal({
    title: "Textos de la página",
    fields: [
      h("div", { class: "full" }, field("Nombre del servicio", input({ name: "title", maxlength: "60", value: cfg.title }))),
      h("div", { class: "full" }, field("Titular", input({ name: "headline", maxlength: "120", value: cfg.headline }))),
      h("div", { class: "full" }, field("Descripción", h("textarea", { class: "input", name: "subtitle", maxlength: "400", rows: "3", value: cfg.subtitle }))),
      h("div", { class: "full" }, field("Email de contacto", input({ name: "email", type: "email", maxlength: "254", value: cfg.email, placeholder: "hola@midominio.com" }),
        "Aparece en el pie y en «Contactar» si no tienes el registro con pago abierto.")),
      h("div", { class: "full" }, field("Aviso legal (pie de página)", h("textarea", { class: "input", name: "legal", maxlength: "4000", rows: "4", value: cfg.legal,
        placeholder: "Razón social, NIF, dirección…" }))),
    ],
    onSubmit: async (fd) => {
      cfg = await api("PUT", "/api/admin/site", { title: fd.get("title"), headline: fd.get("headline"), subtitle: fd.get("subtitle"),
        email: fd.get("email"), legal: fd.get("legal") });
      toast("Textos guardados");
      draw();
    },
  });
  const draw = () => {
    const ip = cfg.server_ips[0] || "IP del servidor";
    const domInput = input({ value: cfg.domains.join(", "), placeholder: "midominio.com, www.midominio.com", class: "input mono", autocapitalize: "off", spellcheck: "false" });
    fill(card,
      h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Página pública" }),
        h("div", { class: "note", text: "Una web de presentación de tu servicio con tus planes, en tu propio dominio (distinto del de la VPN). Desde ella tus clientes entran a su cuenta o contratan un plan." })),
        cfg.enabled && cfg.url ? h("a", { class: "btn", href: cfg.url, target: "_blank", rel: "noopener" }, icon("globe"), "Ver página") : null),
      h("div", { class: "grid", style: { gap: "14px" } },
        h("div", { class: "input-group" }, domInput,
          h("button", { class: "btn primary", onClick: () => save({ domains: splitList(domInput.value) }, "Dominio guardado") }, "Guardar")),
        h("div", { class: "cell-flex", style: { flexWrap: "wrap" } },
          h("label", { class: "switch" }, h("input", { type: "checkbox", checked: cfg.enabled, disabled: !cfg.domains.length,
            onChange: (e) => save({ enabled: e.target.checked }, e.target.checked ? "Página publicada" : "Página desactivada") }),
            h("span", { class: "track" }), h("span", { text: "Publicar la página" })),
          h("button", { class: "btn", onClick: editTexts }, icon("edit"), "Textos"),
          cfg.domains.length ? h("button", { class: "btn", onClick: (e) => { e.currentTarget.disabled = true; check(); } }, icon("refresh"), "Comprobar") : null),
        cfg.enabled ? domainStatusBlock(status) : null,
        cfg.has_plans ? null : h("p", { class: "help" }, "Aún no tienes planes visibles: créalos en ", h("a", { href: "#/billing", text: "Facturación" }),
          " para que aparezcan con su precio."),
        cfg.has_plans && !cfg.signup ? h("p", { class: "help" }, "Para que los visitantes puedan contratar desde la página, activa el «Registro público» en ",
          h("a", { href: "#/billing", text: "Facturación" }), ".") : null,
        h("ol", { class: "steps" },
          h("li", null, "En tu proveedor de dominios crea un registro ", h("b", { text: "A" }), " de cada dominio (p. ej. ", h("code", { text: cfg.domains[0] || "midominio.com" }),
            " y www) hacia ", h("code", { text: ip }), "."),
          h("li", { text: "Escríbelos arriba, guarda y activa «Publicar la página». El certificado HTTPS se emite solo." }),
          h("li", null, "Tus clientes entran desde el botón «Entrar» (el panel queda en ", h("code", { text: `${cfg.domains[0] || "midominio.com"}/app` }), ")."))));
  };
  api("GET", "/api/admin/site").then((d) => { cfg = d; draw(); if (cfg.enabled && cfg.domains.length) check(); })
    .catch((e) => fill(card, h("p", { class: "note", text: e.message })));
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
      siteCard(),
      endpointCard(),
      exitsCard(),
      alertsConfigCard(),
      backupCard(),
      updatesCard(),
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
      o.tenants === 0 ? h("div", { class: "banner" }, icon("refresh"),
        h("span", null, "¿Vienes de otro servidor? ", h("a", { href: "#", onClick: (e) => { e.preventDefault(); restoreModal(); }, text: "Restaura una copia de seguridad" }),
          " y recupera clientes, dispositivos y ajustes.")) : null,
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
          o.system && o.system.ready ? h("a", { class: "sys-mini", href: "#/server", title: "Ver el monitor del servidor" },
            [["CPU", o.system.cpu], ["Memoria", o.system.memory.pct], ["Disco", o.system.disk.pct]].map(([label, pct]) =>
              h("div", { class: "sys-row" }, h("span", { text: label }), meter(pct), h("b", { text: fmtPct(pct) })))) : null,
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
            h("div", null, h("div", { class: "name" }, t.name, t.billing_status === "free" ? h("span", { class: "badge ok tiny", text: "Gratis" }) : null),
              h("div", { class: "meta", text: t.username })))),
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
      h("div", { class: "full field" }, switchEl("free", false, "Cliente gratuito (proyecto propio)"),
        h("div", { class: "help", text: "Nunca se le cobra ni se suspende por pagos, y no ve planes que contratar." })),
      h("div", { class: "full" }, field("Notas", h("textarea", { class: "input", name: "notes", maxlength: "500", placeholder: "Plan, contacto, referencia…" }))),
    ],
    onSubmit: async (fd) => {
      const t = await api("POST", "/api/admin/tenants", {
        name: fd.get("name"), username: fd.get("username"), password: fd.get("password"),
        max_devices: Number(fd.get("max_devices")), notes: fd.get("notes") || "", free: fd.get("free") === "on",
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
        h("span", { class: `badge ${t.enabled ? "ok" : "off"}`, text: t.enabled ? "Activo" : t.suspended_reason === "billing" ? "Suspendido por impago" : "Suspendido" }),
        t.billing_status && t.billing_status !== "none" ? statusBadge(t.billing_status) : null,
        h("span", { class: "mono", text: t.network }),
        t.must_change ? h("span", { class: "badge warn", text: "Pendiente de primer acceso" }) : null,
        filterBadges(t.filters)),
      [
        h("a", { class: "btn", href: `#/clients/${t.id}/activity` }, icon("activity"), "Actividad"),
        h("a", { class: "btn", href: `#/clients/${t.id}/users` }, icon("users"), "Usuarios"),
        h("a", { class: "btn", href: `#/plan/${t.id}` }, icon("card"), "Plan"),
        h("a", { class: "btn", href: `#/clients/${t.id}/filters` }, icon("shield"), "Filtros"),
        h("a", { class: "btn", href: `#/clients/${t.id}/dns` }, icon("server"), "DNS"),
        h("a", { class: "btn", href: `#/clients/${t.id}/services` }, icon("globe"), "Servicios"),
        h("a", { class: "btn", href: `#/clients/${t.id}/ports` }, icon("plug"), "Puertos"),
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
      field("Máx. puertos abiertos", input({ name: "max_forwards", type: "number", min: "0", max: "100", value: String(t.max_forwards), required: true }),
        "0 = no puede abrir puertos."),
      field("Red", input({ value: t.network, disabled: true })),
      h("div", { class: "full field" }, switchEl("allow_exits", t.allow_exits, "Puede usar salidas por país")),
      h("div", { class: "full" }, field("Notas", h("textarea", { class: "input", name: "notes", maxlength: "500", value: t.notes }))),
    ],
    onSubmit: async (fd) => {
      await api("PATCH", `/api/admin/tenants/${t.id}`, { name: fd.get("name"), max_devices: Number(fd.get("max_devices")),
        max_forwards: Number(fd.get("max_forwards")), allow_exits: fd.get("allow_exits") === "on", notes: fd.get("notes") || "" });
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
  const member = state.me.role === "member";
  const full = !member && devices.length >= max;
  const canAdd = !member || state.me.can_create;
  return h("div", { class: "card" },
    h("div", { class: "card-head" },
      h("div", null, h("h2", { text: member ? "Mis dispositivos" : "Dispositivos" }),
        h("div", { class: "note", text: member ? `${devices.length} a tu nombre` : `${devices.length} de ${max} usados` })),
      canAdd ? h("button", { class: "btn primary", disabled: full, title: full ? "Límite alcanzado" : null, onClick: () => newDeviceModal(tenantId, onChange) },
        icon("plus"), "Añadir dispositivo") : null),
    devices.length
      ? h("div", { class: "table-wrap" }, h("table", { class: "cards" },
        h("thead", null, h("tr", null, h("th", { text: "Dispositivo" }), h("th", { text: "IP" }), h("th", { class: "hide-sm", text: "Último contacto" }),
          h("th", { class: "hide-sm", text: "Tráfico" }), h("th", { class: "hide-sm", text: "Modo" }), h("th"))),
        h("tbody", null, devices.map((d) => deviceRow(d, onChange)))))
      : h("div", { class: "empty" }, icon("devices"), h("h2", { text: "Sin dispositivos" }),
        h("p", { text: canAdd ? "Añade un portátil, móvil o servidor y escanea el QR con la app de WireGuard."
          : "Pide al responsable de tu empresa que te asigne un dispositivo." })));
}

function deviceRow(d, onChange) {
  const status = !d.enabled ? ["dis", "Deshabilitado"] : d.online ? ["on", "En línea"] : ["", "Desconectado"];
  return h("tr", null,
    h("td", { class: "primary" }, h("div", { class: "cell-flex" }, h("span", { class: `dot ${status[0]}`, title: status[1] }),
      h("div", null, h("div", { class: "name", text: d.name }),
        h("div", { class: "meta", text: [d.endpoint ? `${status[1]} · ${d.endpoint}` : status[1], d.member_name,
          d.monitor ? "vigilado" : null, d.dns_filter ? null : "sin filtros"].filter(Boolean).join(" · ") })))),
    h("td", { class: "mono", "data-label": "IP", text: d.ip }),
    h("td", { class: "hide-sm", "data-label": "Último contacto", text: ago(d.last_handshake) }),
    h("td", { class: "hide-sm", "data-label": "Tráfico", text: `↓ ${fmtBytes(d.tx)} · ↑ ${fmtBytes(d.rx)}` }),
    h("td", { class: "hide-sm", "data-label": "Modo" }, d.kind === "router"
      ? h("span", { class: "badge accent", title: d.lan_networks.join(", ") }, icon("router"), `Router · ${d.lan_networks.join(", ")}`)
      : h("span", { class: `badge ${d.full_tunnel ? "accent" : ""}` }, icon(d.full_tunnel ? "globe" : "network"), d.full_tunnel ? "Todo el tráfico" : "Solo red privada")),
    h("td", { class: "actions aside" },
      h("button", { class: "btn ghost icon", title: "Actividad", onClick: () => deviceActivityModal(d) }, icon("activity")),
      h("button", { class: "btn ghost icon", title: "Configuración y QR", onClick: () => deviceConfigModal(d) }, icon("qr")),
      d.kind === "router" ? null : h("button", { class: "btn ghost icon", title: "Enlace de instalación", onClick: () => installLinkModal(d) }, icon("share")),
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

async function newDeviceModal(tenantId, onDone) {
  const member = state.me.role === "member";
  const [members, ex] = await Promise.all([memberOptions(tenantId), exitOptions(tenantId)]);
  const tunnel = tunnelField(true);
  const exitBox = exitField(ex, null);
  const lan = lanField("");
  lan.hidden = true;
  lan.querySelector("input").required = false;
  const kindSel = h("div", { class: "segmented full" },
    ["device", "router"].map((k) => h("label", null,
      h("input", { type: "radio", name: "kind", value: k, checked: k === "device", onChange: () => {
        const router = k === "router";
        tunnel.hidden = router;
        if (exitBox) exitBox.hidden = router;
        lan.hidden = !router;
        lan.querySelector("input").required = router;
      } }),
      h("span", null, icon(k === "router" ? "router" : "devices"), k === "router" ? "Router (red completa)" : "Dispositivo"))));
  formModal({
    title: "Añadir dispositivo",
    submitLabel: "Crear",
    fields: [
      member ? null : kindSel,
      h("div", { class: "full" }, field("Nombre", input({ name: "name", required: true, maxlength: "48", placeholder: member ? "Mi portátil, mi iPhone…" : "Portátil de Ana, iPhone, MikroTik oficina…" }))),
      tunnel,
      lan,
      exitBox,
      memberField(members, null),
    ],
    onSubmit: async (fd) => {
      const router = fd.get("kind") === "router";
      const memberId = fd.get("member_id") ? Number(fd.get("member_id")) : 0;
      const body = router
        ? { name: fd.get("name"), kind: "router", lan_networks: splitList(fd.get("lan_networks")), full_tunnel: false }
        : { name: fd.get("name"), full_tunnel: fd.get("full_tunnel") === "on" };
      if (state.me.role === "admin") body.tenant_id = tenantId;
      if (memberId) body.member_id = memberId;
      if (!router && fd.get("exit_id") !== null && Number(fd.get("exit_id")) >= 0) body.exit_id = Number(fd.get("exit_id"));
      const d = await api("POST", "/api/devices", body);
      onDone();
      deviceConfigModal(d, true);
    },
  });
}

async function memberOptions(tenantId) {
  if (state.me.role === "member") return null;
  try {
    const qs = state.me.role === "admin" ? `?tenant_id=${tenantId}` : "";
    return (await api("GET", `/api/members${qs}`)).members;
  } catch { return null; }
}
function memberField(members, current) {
  if (!members || !members.length) return null;
  return h("div", { class: "full" }, field("Usuario",
    h("select", { class: "input", name: "member_id" },
      h("option", { value: "0", text: "Sin asignar (sólo el responsable)", selected: !current }),
      members.map((m) => h("option", { value: String(m.id), text: m.name, selected: m.id === current }))),
    "El usuario asignado lo ve en su cuenta y puede descargar su configuración."));
}
const COUNTRIES = { ES: "España", DE: "Alemania", FR: "Francia", GB: "Reino Unido", NL: "Países Bajos", IT: "Italia", PT: "Portugal",
  IE: "Irlanda", BE: "Bélgica", CH: "Suiza", AT: "Austria", SE: "Suecia", NO: "Noruega", DK: "Dinamarca", FI: "Finlandia", PL: "Polonia",
  CZ: "Chequia", RO: "Rumanía", US: "Estados Unidos", CA: "Canadá", MX: "México", BR: "Brasil", AR: "Argentina", CL: "Chile",
  CO: "Colombia", PE: "Perú", UY: "Uruguay", JP: "Japón", KR: "Corea del Sur", SG: "Singapur", HK: "Hong Kong", IN: "India",
  AU: "Australia", NZ: "Nueva Zelanda", ZA: "Sudáfrica", AE: "Emiratos Árabes", IL: "Israel", TR: "Turquía" };
function flag(code) {
  return code && /^[A-Z]{2}$/.test(code) ? String.fromCodePoint(...[...code].map((ch) => 0x1f1a5 + ch.charCodeAt(0))) : "🌐";
}
function countrySelect(name, value) {
  return h("select", { class: "input", name, required: true },
    h("option", { value: "", text: "Elige país…", disabled: true, selected: !value }),
    Object.entries(COUNTRIES).sort((a, b) => a[1].localeCompare(b[1], "es")).map(([code, label]) =>
      h("option", { value: code, selected: code === value, text: `${flag(code)} ${label}` })));
}
async function exitOptions(tenantId) {
  try {
    const qs = state.me.role === "admin" ? `?tenant_id=${tenantId}` : "";
    const r = await api("GET", `/api/exits${qs}`);
    return r.allowed && r.exits.length ? r : null;
  } catch { return null; }
}
function exitLabel(ex, id) {
  if (!id) return `${flag(ex.main.country)} ${ex.main.name}`;
  const e = ex.exits.find((x) => x.id === id);
  return e ? `${flag(e.country)} ${e.name}${e.online ? "" : " (sin conexión)"}` : "Salida retirada";
}
function exitField(ex, current, { inherit = true } = {}) {
  if (!ex) return null;
  const opts = [];
  if (inherit) opts.push(h("option", { value: "-1", selected: current === null || current === undefined, text: `Como el resto de la red (${exitLabel(ex, ex.tenant_default)})` }));
  opts.push(h("option", { value: "0", selected: current === 0, text: exitLabel(ex, 0) }));
  ex.exits.forEach((e) => opts.push(h("option", { value: String(e.id), selected: current === e.id, text: exitLabel(ex, e.id) })));
  return h("div", { class: "full exit-field" }, field("Salida a Internet", h("select", { class: "input", name: "exit_id" }, opts),
    "País desde el que navega este dispositivo (sólo con «Enviar todo el tráfico por la VPN»)."));
}

function monitorField(checked) {
  return h("div", { class: "full field" },
    switchEl("monitor", checked, "Avisar si se desconecta"),
    h("div", { class: "help", text: "Envía un aviso (Telegram, email o notificación) si deja de conectar unos minutos, y otro cuando vuelve." }));
}

async function editDeviceModal(d, onDone) {
  const isMember = state.me.role === "member";
  const [members, ex] = await Promise.all([memberOptions(d.tenant_id), d.kind === "router" ? null : exitOptions(d.tenant_id)]);
  formModal({
    title: "Editar dispositivo",
    fields: [
      h("div", { class: "full" }, field("Nombre", input({ name: "name", required: true, maxlength: "48", value: d.name }))),
      isMember ? null : h("div", { class: "full" }, field("Nombre de red (DNS)",
        input({ name: "hostname", required: true, maxlength: "63", value: d.hostname || "", pattern: "[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?",
          autocapitalize: "off", spellcheck: false, class: "input mono" }),
        "Los demás dispositivos del cliente lo encuentran por este nombre (p. ej. portatil-ana o portatil-ana.vpn).")),
      d.kind === "router" ? lanField(d.lan_networks.join(", ")) : tunnelField(d.full_tunnel),
      memberField(members, d.member_id),
      exitField(ex, d.exit_id),
      monitorField(d.monitor),
      isMember ? null : h("div", { class: "full field" },
        switchEl("dns_filter", d.dns_filter, "Aplicar los filtros de navegación"),
        h("div", { class: "help", text: "Desactívalo para que este dispositivo (p. ej. el de un adulto) navegue sin los filtros del cliente." })),
      h("p", { class: "note full", style: { margin: 0 }, text: "Si cambias el modo de túnel, vuelve a importar la configuración en el dispositivo." }),
    ],
    onSubmit: async (fd) => {
      const body = { name: fd.get("name"), monitor: fd.get("monitor") === "on",
        ...(d.kind === "router" ? { lan_networks: splitList(fd.get("lan_networks")) } : { full_tunnel: fd.get("full_tunnel") === "on" }) };
      if (!isMember) Object.assign(body, { dns_filter: fd.get("dns_filter") === "on", hostname: fd.get("hostname") });
      if (fd.get("member_id") !== null) body.member_id = Number(fd.get("member_id"));
      if (fd.get("exit_id") !== null) body.exit_id = Number(fd.get("exit_id"));
      await api("PATCH", `/api/devices/${d.id}`, body);
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

/* ------------------------------------------------------------------ reenvío de puertos */
const PROTO_LABEL = { tcp: "TCP", udp: "UDP", both: "TCP + UDP" };

function portModal(ctx, fw, onDone) {
  const isNew = !fw;
  const listId = "port-targets";
  const pub = input({ name: "public_port", required: true, type: "number", min: String(ctx.minPort), max: "65535",
    value: fw ? fw.public_port : (ctx.suggested || ""), disabled: !isNew, inputmode: "numeric" });
  const fields = [
    h("div", { class: "full" }, field("Protocolo",
      h("div", { class: "segmented" }, ["tcp", "udp", "both"].map((k) => h("label", null,
        h("input", { type: "radio", name: "proto", value: k, disabled: !isNew, checked: (fw ? fw.proto : "tcp") === k }),
        h("span", { text: PROTO_LABEL[k] })))))),
    field("Puerto público", pub, isNew ? `El que se abre en el servidor (${ctx.minPort}–65535).` : "No se puede cambiar: crea otro si lo necesitas."),
    field("Descripción", input({ name: "description", maxlength: "60", value: fw ? fw.description : "", placeholder: "Escritorio remoto, cámara…" })),
    field("IP del equipo", input({ name: "target_ip", required: true, maxlength: "15", value: fw ? fw.target_ip : "", list: listId,
      placeholder: ctx.networks[0].replace(/0\/\d+$/, "50"), class: "input mono", inputmode: "decimal" }), `De tu red (${ctx.networks.join(", ")}).`),
    field("Puerto del equipo", input({ name: "target_port", required: true, type: "number", min: "1", max: "65535", value: fw ? fw.target_port : "", placeholder: "3389", inputmode: "numeric" })),
    h("datalist", { id: listId }, ctx.devices.filter((d) => d.kind !== "router").map((d) => h("option", { value: d.ip, text: d.name }))),
  ];
  formModal({
    title: isNew ? "Abrir puerto" : `Puerto ${fw.public_port}`,
    submitLabel: isNew ? "Abrir puerto" : "Guardar",
    fields,
    onSubmit: async (fd) => {
      const body = { target_ip: fd.get("target_ip").trim(), target_port: Number(fd.get("target_port")), description: fd.get("description") || "" };
      if (isNew) {
        Object.assign(body, { proto: fd.get("proto"), public_port: Number(fd.get("public_port")) });
        if (ctx.isAdmin) body.tenant_id = ctx.tenantId;
        await api("POST", "/api/forwards", body);
        toast("Puerto abierto");
      } else {
        await api("PATCH", `/api/forwards/${fw.id}`, body);
        toast("Puerto actualizado");
      }
      onDone();
    },
  });
}

async function portsView(main, tenantId) {
  const isAdmin = state.me.role === "admin";
  const qs = isAdmin ? `?tenant_id=${tenantId}` : "";
  const [tenant, devices] = await Promise.all([
    isAdmin ? api("GET", `/api/admin/tenants/${tenantId}`) : Promise.resolve({ name: state.me.name }),
    api("GET", `/api/devices${qs}`)]);
  let data = await api("GET", `/api/forwards${qs}`);
  const status = {};
  const body = h("div");
  const ctx = () => ({ isAdmin, tenantId, devices, networks: data.networks, minPort: data.min_port, suggested: data.suggested_port });
  const reload = async () => { data = await api("GET", `/api/forwards${qs}`); draw(); };
  const run = async (fn, msg) => { try { await fn(); toast(msg); await reload(); } catch (e) { toast(e.message, "err"); } };
  const check = async (fw) => {
    status[fw.id] = "loading";
    draw();
    try { status[fw.id] = (await api("GET", `/api/forwards/${fw.id}/status`)).target; } catch (e) { delete status[fw.id]; toast(e.message, "err"); }
    draw();
  };
  const add = () => portModal(ctx(), null, reload);
  let addBtn = null;

  const row = (fw) => {
    const st = status[fw.id];
    return h("div", { class: "card service" },
      h("div", { class: "card-head" },
        h("div", { class: "grow" },
          h("div", { class: "cell-flex", style: { flexWrap: "wrap" } },
            h("span", { class: "mono svc-name", text: `${data.public_host}:${fw.public_port}` }),
            h("span", { class: "badge accent", text: PROTO_LABEL[fw.proto] }),
            h("span", { class: `badge ${fw.enabled ? "ok" : "off"}`, text: fw.enabled ? "Abierto" : "Cerrado" }),
            fw.description ? h("span", { class: "note", text: fw.description }) : null),
          h("div", { class: "meta mono", text: `→ ${fw.target_ip}:${fw.target_port}${fw.target_name ? `  (${fw.target_name})` : ""}` })),
        h("div", { class: "cell-flex" },
          fw.proto !== "udp" ? h("button", { class: "btn sm", disabled: st === "loading", onClick: () => check(fw) }, icon("refresh"), st === "loading" ? "Comprobando…" : "Comprobar") : null,
          h("button", { class: "btn ghost icon", title: "Editar", onClick: () => portModal(ctx(), fw, () => { delete status[fw.id]; reload(); }) }, icon("edit")),
          h("button", { class: "btn ghost icon", title: fw.enabled ? "Cerrar" : "Abrir", onClick: () =>
            run(() => api("PATCH", `/api/forwards/${fw.id}`, { enabled: !fw.enabled }), fw.enabled ? "Puerto cerrado" : "Puerto abierto") }, icon("power")),
          h("button", { class: "btn ghost icon", title: "Eliminar", onClick: async () => {
            if (await confirmDialog({ title: "Eliminar puerto", message: `El puerto ${fw.public_port} dejará de llegar a ${fw.target_ip}.`, confirmLabel: "Eliminar" })) {
              run(() => api("DELETE", `/api/forwards/${fw.id}`), "Puerto eliminado");
            }
          } }, icon("trash")))),
      st && st !== "loading" ? h("div", { class: "domain-status" },
        checkLine(st.ok, "El equipo responde en ese puerto", `Sin respuesta del equipo: ${st.error}`)) : null);
  };

  const draw = () => {
    if (addBtn) addBtn.disabled = data.forwards.length >= data.max;
    fill(body,
      data.max === 0 ? h("div", { class: "banner" }, icon("alert"), "Tu plan no incluye puertos abiertos. Pídeselo a tu proveedor.") : null,
      data.forwards.length ? data.forwards.map(row) : h("div", { class: "card empty" }, icon("plug"),
        h("h2", { text: "Ningún puerto abierto" }),
        h("p", { text: "Da acceso desde Internet a un equipo de tu red por un puerto: escritorio remoto, cámaras (RTSP), un servidor de juegos, SSH…" }),
        data.max > 0 ? h("button", { class: "btn primary", onClick: add }, icon("plus"), "Abrir puerto") : null),
      h("div", { class: "card" }, h("h3", { text: "Cómo funciona" }),
        h("ol", { class: "steps" },
          h("li", null, "Desde Internet se conecta a ", h("code", { text: `${data.public_host}:<puerto público>` }), "."),
          h("li", { text: "El servidor lo lleva por el túnel al equipo y puerto que indiques. El equipo debe estar conectado a la VPN (o en la LAN de tu router)." }),
          h("li", { text: "El equipo verá la conexión como si viniera del servidor de la VPN: si filtra por IP, permite la red de la VPN." })),
        h("p", { class: "note", style: { margin: "10px 0 0" } }, icon("shield"),
          ` Cualquiera en Internet puede intentar conectar a un puerto abierto: ábrelo sólo para servicios con su propia contraseña y ciérralo cuando no lo uses. Usados: ${data.forwards.length} de ${data.max}. `,
          "Para webs (HTTP) usa mejor Servicios: tienen HTTPS y nombre propio.")),
    );
    body.querySelectorAll(".note > svg").forEach((svg) => Object.assign(svg.style, { width: "14px", height: "14px", verticalAlign: "-2px" }));
  };

  const crumbs = isAdmin ? [h("a", { href: "#/clients", text: "Clientes" }), " / ", h("a", { href: `#/clients/${tenantId}`, text: tenant.name }), " / Puertos"] : null;
  addBtn = data.max > 0 ? h("button", { class: "btn primary", onClick: add }, icon("plus"), "Abrir puerto") : null;
  fill(main, pageHead("Puertos abiertos", `Accesos TCP/UDP desde Internet a equipos de la red de ${tenant.name}`, addBtn, crumbs), body);
  draw();
}

/* ------------------------------------------------------------------ gráficos */
const RANGE_LABEL = { "24h": "24 h", "7d": "7 días", "30d": "30 días", "12m": "12 meses" };
const MONTHS = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"];
const WEEKDAYS = ["dom", "lun", "mar", "mié", "jue", "vie", "sáb"];

function bucketLabel(unit, key, long = false) {
  if (unit === "hour") {
    const d = new Date(key * 3600 * 1000);
    const hh = `${String(d.getHours()).padStart(2, "0")}:00`;
    return long ? `${d.getDate()} ${MONTHS[d.getMonth()]}, ${hh}` : hh;
  }
  if (unit === "day") {
    const [y, m, dd] = key.split("-").map(Number);
    const d = new Date(y, m - 1, dd);
    return long ? `${WEEKDAYS[d.getDay()]} ${dd} ${MONTHS[m - 1]} ${y}` : `${dd} ${MONTHS[m - 1]}`;
  }
  const [y, m] = key.split("-").map(Number);
  return long ? `${MONTHS[m - 1]} ${y}` : MONTHS[m - 1];
}

function niceMax(v) {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  return [1, 2, 2.5, 5, 10].map((x) => x * p).find((x) => x >= v);
}
function niceBytes(v) { // tope del eje en múltiplos «redondos» de KB/MB/GB
  if (v <= 0) return 1024;
  const i = Math.max(0, Math.floor(Math.log(v) / Math.log(1024)));
  const n = niceMax(v / 1024 ** i);
  return n >= 1000 ? 1024 ** (i + 1) : n * 1024 ** i;
}
function axisBytes(n) { return fmtBytes(n).replace(/\.0 /, " "); }
function fmtNum(n) { return Number(n || 0).toLocaleString("es-ES"); }

/* Barras apiladas en HTML (nítidas a cualquier ancho). series: [{key, label, cls}] de abajo arriba. */
function barChart({ unit, buckets, series, fmt, axis = fmt, max: maxFn = niceMax, empty = "Sin datos en este periodo" }) {
  const totals = buckets.map((b) => series.reduce((a, s) => a + (b[s.key] || 0), 0));
  const top = maxFn(Math.max(...totals, 0));
  const tip = h("div", { class: "chart-tip", hidden: true });
  const plot = h("div", { class: "chart-plot" });
  [1, 0.5, 0].forEach((f) => plot.append(h("div", { class: "chart-grid", style: { bottom: `${f * 100}%` } },
    h("span", { text: f ? axis(top * f) : "0" }))));
  const step = buckets.length > 24 ? 5 : buckets.length > 12 ? 3 : buckets.length > 8 ? 2 : 1;
  const cols = h("div", { class: "chart-cols" });
  const xs = h("div", { class: "chart-x" });
  let pinned = null;
  const show = (i, col) => {
    const b = buckets[i];
    fill(tip, h("b", { text: bucketLabel(unit, b.key, true) }),
      ...series.slice().reverse().map((s) => h("div", { class: "tip-row" }, h("i", { class: `sw ${s.cls}` }), h("span", { text: s.label }), h("em", { text: fmt(b[s.key] || 0) }))),
      series.length > 1 ? h("div", { class: "tip-row total" }, h("span", { text: "Total" }), h("em", { text: fmt(totals[i]) })) : null);
    tip.hidden = false;
    const box = plot.getBoundingClientRect();
    const r = col.getBoundingClientRect();
    const x = r.left - box.left + r.width / 2;
    tip.style.left = `${Math.min(Math.max(x, 70), box.width - 70)}px`;
    cols.querySelectorAll(".chart-col.hover").forEach((el) => el.classList.remove("hover"));
    col.classList.add("hover");
  };
  const hide = () => { if (pinned === null) { tip.hidden = true; cols.querySelectorAll(".chart-col.hover").forEach((el) => el.classList.remove("hover")); } };
  buckets.forEach((b, i) => {
    const col = h("div", { class: "chart-col", tabindex: "0", "aria-label": `${bucketLabel(unit, b.key, true)}: ${fmt(totals[i])}`,
      onMouseenter: (e) => show(i, e.currentTarget), onMouseleave: hide, onFocus: (e) => show(i, e.currentTarget), onBlur: () => { pinned = null; hide(); },
      onClick: (e) => { pinned = pinned === i ? null : i; if (pinned === null) { tip.hidden = true; } else show(i, e.currentTarget); } });
    const stack = h("div", { class: "chart-stack", style: { height: `${(100 * totals[i]) / top}%` } });
    const nonzero = series.filter((s) => b[s.key] > 0);
    nonzero.forEach((s, j) => stack.append(h("div", { class: `chart-seg ${s.cls}${j === nonzero.length - 1 ? " end" : ""}`,
      style: { flexGrow: String(b[s.key]) } })));
    col.append(stack);
    cols.append(col);
    xs.append(h("span", { text: i % step === 0 || i === buckets.length - 1 && step === 1 ? bucketLabel(unit, b.key) : "" }));
  });
  plot.append(cols, tip);
  const table = h("table", { class: "chart-table", hidden: true },
    h("thead", null, h("tr", null, h("th", { text: "Periodo" }), ...series.map((s) => h("th", { text: s.label })))),
    h("tbody", null, buckets.map((b) => h("tr", null, h("td", { text: bucketLabel(unit, b.key, true) }), ...series.map((s) => h("td", { text: fmt(b[s.key] || 0) }))))));
  const tableBtn = h("button", { class: "btn ghost sm", type: "button", onClick: () => {
    table.hidden = !table.hidden;
    tableBtn.textContent = table.hidden ? "Ver tabla" : "Ver gráfico";
    plot.hidden = xs.hidden = !table.hidden;
  } }, "Ver tabla");
  const legend = h("div", { class: "chart-legend" },
    series.length > 1 ? series.map((s) => h("span", null, h("i", { class: `sw ${s.cls}` }), s.label)) : null,
    h("span", { class: "grow" }), tableBtn);
  const wrap = h("div", { class: "chart" }, legend, plot, xs, h("div", { class: "table-wrap" }, table));
  if (!totals.some(Boolean)) plot.append(h("div", { class: "chart-empty", text: empty }));
  return wrap;
}

const TRAFFIC_SERIES = [{ key: "tx", label: "Descarga", cls: "s1" }, { key: "rx", label: "Subida", cls: "s2" }];
const DNS_SERIES = [{ key: "allowed", label: "Permitidas", cls: "s1" }, { key: "blocked", label: "Bloqueadas", cls: "s2" }];

function rangePicker(value, onChange, labels = RANGE_LABEL) {
  const name = `range-${Math.random().toString(36).slice(2)}`;
  return h("div", { class: "segmented compact" }, Object.entries(labels).map(([k, label]) => h("label", null,
    h("input", { type: "radio", name, checked: k === value, onChange: () => onChange(k) }),
    h("span", { text: label }))));
}

function eventList(events, { showTenant = false, showDevice = true } = {}) {
  if (!events.length) return h("p", { class: "note", style: { margin: 0 }, text: "Todavía no hay conexiones registradas." });
  return h("div", { class: "event-list" }, events.map((e) => h("div", { class: `event ${e.kind}` },
    h("span", { class: `dot ${e.kind === "online" ? "on" : ""}` }),
    h("div", { class: "grow" },
      h("div", { class: "name" }, showDevice ? h("b", { text: e.device }) : null, showDevice ? " " : "",
        e.kind === "online" ? "se conectó" : "se desconectó", showTenant ? h("span", { class: "note", text: ` · ${e.tenant}` }) : null),
      h("div", { class: "meta", text: [new Date(e.ts * 1000).toLocaleString(), e.kind === "online" && e.endpoint ? `desde ${e.endpoint}` : null].filter(Boolean).join(" · ") })))));
}

function rankList(items, total, onClick) {
  if (!items.length) return h("p", { class: "note", style: { margin: 0 }, text: "Sin tráfico en este periodo." });
  return h("div", { class: "rank-list" }, items.map((x) => h(onClick ? "button" : "div", { class: "rank", type: onClick ? "button" : null, onClick: onClick ? () => onClick(x) : null },
    h("div", { class: "rank-head" }, h("span", { class: "name", text: x.name }), h("span", { class: "mono", text: fmtBytes(x.rx + x.tx) })),
    h("div", { class: "rank-bar" }, h("span", { style: { width: `${total ? Math.max(2, (100 * (x.rx + x.tx)) / total) : 0}%` } })))));
}

/* ------------------------------------------------------------------ admin: servidor */
const SERVER_RANGES = { "1h": "1 h", "24h": "24 h", "7d": "7 días", "30d": "30 días" };
function fmtBits(bytesPerSec) {
  const b = (bytesPerSec || 0) * 8;
  const u = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"];
  const i = b < 1 ? 0 : Math.min(Math.floor(Math.log(b) / Math.log(1000)), u.length - 1);
  return `${(b / 1000 ** i).toFixed(i && b / 1000 ** i < 10 ? 1 : 0)} ${u[i]}`;
}
function fmtUptime(s) {
  if (s == null) return "—";
  const d = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d} d ${hh} h` : hh ? `${hh} h ${m} min` : `${m} min`;
}
function fmtPct(v) { return v == null ? "—" : `${Number(v).toFixed(v < 10 ? 1 : 0)} %`; }
function level(pct) { return pct >= 90 ? "danger" : pct >= 75 ? "warn" : ""; }
function meter(pct) {
  return h("div", { class: `progress meter ${level(pct)}` }, h("span", { style: { width: `${Math.min(100, Math.max(0, pct || 0))}%` } }));
}

/* Líneas en SVG (series temporales con huecos). series: [{key, label, cls, dash}] */
function lineChart({ points, series, fmt, axis = fmt, max = null, range, empty = "Aún no hay datos: el servidor se mide cada 10 segundos." }) {
  const vals = points.flatMap((p) => series.map((s) => p[s.key])).filter((v) => v != null);
  const top = max != null ? max : niceMax(Math.max(...vals, 0) * 1.05 || 1);
  const n = points.length;
  const W = 1000, H = 100;
  const x = (i) => (n > 1 ? (i * W) / (n - 1) : W / 2);
  const y = (v) => H - Math.min(H, (H * v) / top);
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("class", "line-svg");
  series.forEach((s, si) => {
    let line = "", area = "", run = [];
    const close = () => {
      if (!run.length) return;
      const d = run.map(([i, v], j) => `${j ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(2)}`).join("");
      line += d;
      if (si === 0 && !s.dash) area += `${d}L${x(run[run.length - 1][0]).toFixed(1)},${H}L${x(run[0][0]).toFixed(1)},${H}Z`;
      run = [];
    };
    points.forEach((p, i) => { if (p[s.key] == null) close(); else run.push([i, p[s.key]]); });
    close();
    if (area) {
      const a = document.createElementNS("http://www.w3.org/2000/svg", "path");
      a.setAttribute("d", area); a.setAttribute("class", `area ${s.cls}`);
      svg.append(a);
    }
    const l = document.createElementNS("http://www.w3.org/2000/svg", "path");
    l.setAttribute("d", line || "M0,0"); l.setAttribute("class", `line ${s.cls}${s.dash ? " dash" : ""}`);
    l.setAttribute("vector-effect", "non-scaling-stroke");
    svg.append(l);
  });
  const timeLabel = (t, full) => {
    const d = new Date(t * 1000);
    const hm = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
    const day = `${d.getDate()} ${MONTHS[d.getMonth()]}`;
    if (full) return range === "1h" || range === "24h" ? `${day}, ${hm}` : `${WEEKDAYS[d.getDay()]} ${day}, ${hm}`;
    return range === "1h" || range === "24h" ? hm : day;
  };
  const plot = h("div", { class: "chart-plot line-plot" });
  [1, 0.5, 0].forEach((f) => plot.append(h("div", { class: "chart-grid", style: { bottom: `${f * 100}%` } },
    h("span", { text: f ? axis(top * f) : "0" }))));
  const cursor = h("div", { class: "chart-cursor", hidden: true });
  const tip = h("div", { class: "chart-tip", hidden: true });
  plot.append(svg, cursor, tip);
  const show = (clientX) => {
    const box = plot.getBoundingClientRect();
    const i = Math.max(0, Math.min(n - 1, Math.round(((clientX - box.left) / box.width) * (n - 1))));
    const p = points[i];
    const px = (box.width * x(i)) / W;
    cursor.hidden = false;
    cursor.style.left = `${px}px`;
    fill(tip, h("b", { text: timeLabel(p.t, true) }),
      ...series.map((s) => h("div", { class: "tip-row" }, h("i", { class: `sw ${s.cls}` }), h("span", { text: s.label }),
        h("em", { text: p[s.key] == null ? "sin datos" : fmt(p[s.key]) }))));
    tip.hidden = false;
    tip.style.left = `${Math.min(Math.max(px, 80), box.width - 80)}px`;
  };
  const hide = () => { cursor.hidden = tip.hidden = true; };
  plot.addEventListener("mousemove", (e) => show(e.clientX));
  plot.addEventListener("mouseleave", hide);
  plot.addEventListener("touchstart", (e) => show(e.touches[0].clientX), { passive: true });
  plot.addEventListener("touchmove", (e) => show(e.touches[0].clientX), { passive: true });
  plot.addEventListener("touchend", () => setTimeout(hide, 1500));
  const xs = h("div", { class: "chart-x line-x" });
  const ticks = 5;
  for (let k = 0; k <= ticks; k++) {
    const i = Math.round((k * (n - 1)) / ticks);
    xs.append(h("span", { style: { left: `${(100 * x(i)) / W}%` }, text: n ? timeLabel(points[i].t) : "" }));
  }
  const legend = h("div", { class: "chart-legend" }, series.map((s) => h("span", null, h("i", { class: `sw ${s.cls}${s.dash ? " dash" : ""}` }), s.label)));
  if (!vals.length) plot.append(h("div", { class: "chart-empty", text: empty }));
  return h("div", { class: "chart" }, legend, plot, xs);
}

async function serverView(main) {
  let range = "24h", live = null, hist = null, tick = 0;
  const head = h("div");
  const tiles = h("div", { class: "grid stats sys-tiles" });
  const charts = h("div", { class: "grid sys-charts" });
  const box = (title, sub, chart, wide = false) => h("div", { class: `card${wide ? " span-all" : ""}` },
    h("div", { class: "card-head" }, h("div", null, h("h2", { text: title }), sub ? h("div", { class: "note", text: sub }) : null)), chart);

  const drawLive = () => {
    const l = live;
    fill(head, pageHead("Servidor", [l.hostname, l.os].filter(Boolean).join(" · ") || "Uso de recursos del VPS",
      rangePicker(range, (r) => { range = r; loadHist().catch((e) => toast(e.message, "err")); }, SERVER_RANGES)),
      Object.keys(l.alerts || {}).length ? h("div", { class: "banner danger" }, icon("alert"),
        `Uso alto: ${Object.keys(l.alerts).map((k) => ({ disk: "disco", mem: "memoria", cpu: "CPU" })[k]).join(", ")}. Los administradores han recibido un aviso.`) : null);
    if (!l.ready) { fill(tiles, h("div", { class: "card stat wide" }, h("p", { class: "note", style: { margin: 0 }, text: "Midiendo el servidor… los datos aparecen en unos segundos." }))); return; }
    const tile = (ic, label, value, hint, pct) => h("div", { class: "card stat" },
      h("div", { class: "label" }, icon(ic), label), h("div", { class: "value", text: value }),
      pct != null ? meter(pct) : null, hint ? h("div", { class: "hint", text: hint }) : null);
    fill(tiles,
      tile("activity", "CPU", fmtPct(l.cpu), `${l.cores} núcleo${l.cores > 1 ? "s" : ""}${l.model ? ` · ${l.model}` : ""}`, l.cpu),
      tile("server", "Memoria", fmtPct(l.memory.pct), `${fmtBytes(l.memory.used)} de ${fmtBytes(l.memory.total)}${l.memory.swap_total ? ` · swap ${fmtPct(l.memory.swap_pct)}` : ""}`, l.memory.pct),
      tile("download", "Disco", fmtPct(l.disk.pct), `${fmtBytes(l.disk.used)} de ${fmtBytes(l.disk.total)} · libres ${fmtBytes(l.disk.free)}`, l.disk.pct),
      tile("arrows", "Red", `↓ ${fmtBits(l.net.rx)}`, `↑ ${fmtBits(l.net.tx)}${l.net.iface ? ` · ${l.net.iface}` : ""}`),
      tile("dashboard", "Carga", l.load[0].toFixed(2), `5 min ${l.load[1].toFixed(2)} · 15 min ${l.load[2].toFixed(2)} · ${l.cores} núcleos`, (100 * l.load[0]) / l.cores),
      tile("refresh", "Encendido", fmtUptime(l.uptime), `Kernel ${l.kernel}`));
  };
  const drawHist = () => {
    const p = hist.points;
    const long = range === "7d" || range === "30d";
    const avg = long ? "Media por periodo; la línea discontinua es el máximo." : null;
    const cores = live ? live.cores : 1;
    fill(charts,
      box("CPU", avg, lineChart({ points: p, range, max: 100, fmt: fmtPct, axis: (v) => `${Math.round(v)} %`,
        series: [{ key: "cpu", label: "CPU", cls: "s1" }, ...(long ? [{ key: "cpu_max", label: "Máximo", cls: "s1", dash: true }] : [])] })),
      box("Memoria", avg, lineChart({ points: p, range, max: 100, fmt: fmtPct, axis: (v) => `${Math.round(v)} %`,
        series: [{ key: "mem", label: "RAM", cls: "s1" }, ...(long ? [{ key: "mem_max", label: "Máximo", cls: "s1", dash: true }] : []),
          ...(live && live.memory && live.memory.swap_total ? [{ key: "swap", label: "Swap", cls: "s2" }] : [])] })),
      box("Red", live && live.net && live.net.iface ? `Interfaz ${live.net.iface} (todo el tráfico del VPS)` : null,
        lineChart({ points: p, range, fmt: fmtBits, axis: (v) => fmtBits(v).replace(".0 ", " "),
          series: [{ key: "rx", label: "Entrada", cls: "s1" }, { key: "tx", label: "Salida", cls: "s2" }] })),
      box("Carga", `Procesos esperando CPU; por encima de ${cores} (núcleos) el servidor va saturado.`,
        lineChart({ points: p, range, fmt: (v) => v.toFixed(2), axis: (v) => (v < 10 ? v.toFixed(1) : String(Math.round(v))),
          series: [{ key: "load1", label: "Carga (1 min)", cls: "s2" }] })),
      box("Disco", null, lineChart({ points: p, range, max: 100, fmt: fmtPct, axis: (v) => `${Math.round(v)} %`,
        series: [{ key: "disk", label: "Disco usado", cls: "s2" }] }), true));
  };
  const loadLive = async () => { live = await api("GET", "/api/admin/server/live"); drawLive(); };
  const loadHist = async () => { hist = await api("GET", `/api/admin/server/history?range=${range}`); drawHist(); };

  fill(main, head, tiles, charts);
  fill(tiles, spinnerBlock());
  await loadLive();
  await loadHist();
  every(async () => {
    try {
      await loadLive();
      if (++tick % 6 === 0) await loadHist();   // los gráficos, cada minuto
    } catch { /* reintenta en el siguiente ciclo */ }
  });
}

/* ------------------------------------------------------------------ actividad */
async function activityView(main, tenantId) {
  const isAdmin = state.me.role === "admin";
  const isMember = state.me.role === "member";
  const platform = isAdmin && !tenantId;
  const qs = isAdmin && tenantId ? `&tenant_id=${tenantId}` : "";
  const tenant = isAdmin && tenantId ? await api("GET", `/api/admin/tenants/${tenantId}`) : null;
  let range = "24h";
  const trafficBox = h("div", { class: "card" }, spinnerBlock());
  const dnsBox = h("div", { class: "card" }, spinnerBlock());
  const eventsBox = h("div", { class: "card" }, spinnerBlock());

  const loadTraffic = async () => {
    const t = await api("GET", `/api/history/traffic?range=${range}${qs}`);
    const total = t.total.rx + t.total.tx;
    fill(trafficBox,
      h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Tráfico" }),
        h("div", { class: "big-num" }, fmtBytes(total), h("span", { class: "note", text: ` en ${RANGE_LABEL[range]} · ↓ ${fmtBytes(t.total.tx)} · ↑ ${fmtBytes(t.total.rx)}` })))),
      barChart({ unit: t.unit, buckets: t.buckets, series: TRAFFIC_SERIES, fmt: fmtBytes, axis: axisBytes, max: niceBytes }),
      h("div", { class: "grid two", style: { marginTop: "18px" } },
        platform ? h("div", null, h("h3", { text: "Clientes con más tráfico" }),
          rankList(t.tenants, total, (x) => go(`#/clients/${x.id}/activity`))) : null,
        h("div", null, h("h3", { text: "Dispositivos con más tráfico" }),
          rankList(t.devices.map((x) => ({ ...x, name: platform ? `${x.name} · ${x.tenant}` : x.name })), total))));
  };
  const loadDns = async () => {
    if (isMember) return;
    const d = await api("GET", `/api/history/dns?range=${range}${qs}`);
    if (!d.enabled) { dnsBox.hidden = true; return; }
    const buckets = d.buckets.map((b) => ({ ...b, allowed: b.queries - b.blocked }));
    const pct = d.total.queries ? ((100 * d.total.blocked) / d.total.queries).toFixed(1) : "0";
    fill(dnsBox,
      h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Filtro DNS" }),
        h("div", { class: "big-num" }, fmtNum(d.total.blocked), h("span", { class: "note", text: ` bloqueadas de ${fmtNum(d.total.queries)} consultas (${pct} %)` })))),
      barChart({ unit: d.unit, buckets, series: DNS_SERIES, fmt: fmtNum, empty: "Sin consultas en este periodo" }),
      h("h3", { style: { marginTop: "18px" }, text: "Dominios más bloqueados" }),
      d.top.length ? h("div", { class: "blocked-list" }, d.top.map((x) => h("div", { class: "blocked-row" },
        h("div", { class: "grow mono name", text: x.domain }), h("span", { class: "badge", text: fmtNum(x.count) }))))
        : h("p", { class: "note", style: { margin: 0 }, text: "Nada bloqueado en este periodo." }));
  };
  let events = [];
  const loadEvents = async (more = false) => {
    const before = more && events.length ? `&before=${events[events.length - 1].ts}` : "";
    const r = await api("GET", `/api/history/events?limit=30${qs}${before}`);
    events = more ? events.concat(r.events) : r.events;
    fill(eventsBox,
      h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Conexiones" }),
        h("div", { class: "note", text: "Cuándo se conecta y desconecta cada dispositivo, y desde qué IP pública." }))),
      eventList(events, { showTenant: platform }),
      r.more ? h("button", { class: "btn sm", style: { marginTop: "12px" }, onClick: () => loadEvents(true).catch((e) => toast(e.message, "err")) }, "Cargar más") : null);
  };
  const loadAll = () => Promise.all([loadTraffic(), loadDns(), loadEvents()]).catch((e) => toast(e.message, "err"));

  const crumbs = tenant ? [h("a", { href: "#/clients", text: "Clientes" }), " / ", h("a", { href: `#/clients/${tenantId}`, text: tenant.name }), " / Actividad"] : null;
  const sub = platform ? "Tráfico, filtro DNS y conexiones de toda la plataforma"
    : isMember ? "Tráfico y conexiones de tus dispositivos" : `Tráfico, filtro DNS y conexiones de ${tenant ? tenant.name : "tu red"}`;
  fill(main, pageHead("Actividad", sub, rangePicker(range, (r) => { range = r; loadTraffic().catch((e) => toast(e.message, "err")); loadDns().catch(() => {}); }), crumbs),
    trafficBox, isMember ? null : dnsBox, eventsBox);
  if (isMember) dnsBox.hidden = true;
  await loadAll();
}

async function deviceActivityModal(d) {
  let range = "24h";
  const chartBox = h("div", null, spinnerBlock());
  const load = async () => {
    const t = await api("GET", `/api/history/traffic?range=${range}&device_id=${d.id}`);
    fill(chartBox,
      h("div", { class: "big-num", style: { marginBottom: "10px" } }, fmtBytes(t.total.rx + t.total.tx),
        h("span", { class: "note", text: ` en ${RANGE_LABEL[range]} · ↓ ${fmtBytes(t.total.tx)} · ↑ ${fmtBytes(t.total.rx)}` })),
      barChart({ unit: t.unit, buckets: t.buckets, series: TRAFFIC_SERIES, fmt: fmtBytes, axis: axisBytes, max: niceBytes }));
  };
  const evBox = h("div", null, spinnerBlock());
  const m = modal({
    title: `Actividad de ${d.name}`,
    wide: true,
    body: [rangePicker(range, (r) => { range = r; load().catch((e) => toast(e.message, "err")); }), chartBox,
      h("h3", { style: { margin: "6px 0 0" }, text: "Conexiones" }), evBox],
    actions: [h("button", { class: "btn", onClick: () => m.close() }, "Cerrar")],
  });
  try {
    await load();
    const r = await api("GET", `/api/history/events?limit=15&device_id=${d.id}`);
    fill(evBox, eventList(r.events, { showDevice: false }));
  } catch (e) { toast(e.message, "err"); }
}

/* ------------------------------------------------------------------ avisos */
const CHANNEL_ICON = { telegram: "send", email: "mail", push: "bell" };
const CHANNEL_NAME = { telegram: "Telegram", email: "Email", push: "Notificaciones" };

function pushSupport() {
  if (!window.isSecureContext || !("serviceWorker" in navigator)) return "Las notificaciones necesitan HTTPS: abre el panel con su dominio.";
  if (!("PushManager" in window) || !("Notification" in window)) {
    return isIOS() ? "En iPhone/iPad, instala primero la app (Compartir › Añadir a pantalla de inicio) y actívalas desde ella."
      : "Este navegador no admite notificaciones.";
  }
  return null;
}

async function enablePush(key) {
  const problem = pushSupport();
  if (problem) throw new Error(problem);
  const perm = await Notification.requestPermission();
  if (perm !== "granted") throw new Error("Permiso denegado. Actívalo en los ajustes del navegador para este sitio.");
  const reg = await navigator.serviceWorker.ready;
  let sub = await reg.pushManager.getSubscription();
  if (sub && sub.options && sub.options.applicationServerKey) {
    const cur = btoa(String.fromCharCode(...new Uint8Array(sub.options.applicationServerKey))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    if (cur !== key) { await sub.unsubscribe(); sub = null; }
  }
  if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64uToBuf(key) });
  const j = sub.toJSON();
  return api("POST", "/api/alerts/push", { endpoint: j.endpoint, p256dh: j.keys.p256dh, auth: j.keys.auth, label: deviceLabel() });
}

async function alertsView(main) {
  const role = state.me.role;
  let st = await api("GET", "/api/alerts");
  const body = h("div");
  let watching = null;
  const savePrefs = async (patch) => {
    try { st = await api("PUT", "/api/alerts/prefs", patch); toast("Preferencias guardadas"); draw(); } catch (e) { toast(e.message, "err"); }
  };
  const loadDevices = async () => {
    if (role === "admin") return;
    try { watching = await api("GET", "/api/devices"); } catch { watching = []; }
    draw();
  };

  const connectTelegram = async () => {
    let link;
    try { link = await api("POST", "/api/alerts/telegram/link"); } catch (e) { return toast(e.message, "err"); }
    const before = st.channels.filter((c) => c.kind === "telegram").length;
    let timer = null;
    const m = modal({
      title: "Conectar Telegram",
      body: [
        h("ol", { class: "steps" },
          h("li", null, "Pulsa «Abrir Telegram» y, en el chat con ", h("b", { text: `@${st.available.telegram_bot}` }), ", toca ", h("b", { text: "Iniciar" }), "."),
          h("li", { text: "Vuelve aquí: en cuanto lo hagas, aparecerá conectado." })),
        h("a", { class: "btn primary", href: link.url, target: "_blank", rel: "noopener" }, icon("send"), "Abrir Telegram"),
        h("p", { class: "note", style: { margin: 0 }, text: "El enlace caduca en 15 minutos." }),
      ],
      actions: [h("button", { class: "btn", onClick: () => m.close() }, "Cerrar")],
      onClose: () => clearInterval(timer),
    });
    timer = setInterval(async () => {
      try {
        const now = await api("GET", "/api/alerts");
        if (now.channels.filter((c) => c.kind === "telegram").length > before) {
          st = now; clearInterval(timer); m.close(); toast("Telegram conectado"); draw();
        }
      } catch { /* sigue intentando */ }
    }, 3000);
    setTimeout(() => clearInterval(timer), LINK_POLL_MS);
  };
  const addEmail = () => formModal({
    title: "Avisos por email",
    submitLabel: "Añadir",
    fields: [h("div", { class: "full" }, field("Email", input({ name: "email", type: "email", required: true, maxlength: "254", autocomplete: "email", placeholder: "tu@empresa.com" })))],
    onSubmit: async (fd) => { st = await api("POST", "/api/alerts/email", { email: fd.get("email").trim() }); toast("Email añadido"); draw(); },
  });

  const channelRow = (c) => h("div", { class: "blocked-row" },
    h("span", { class: "channel-icon" }, icon(CHANNEL_ICON[c.kind])),
    h("div", { class: "grow" }, h("div", { class: "name", text: `${CHANNEL_NAME[c.kind]} · ${c.label}` }),
      h("div", { class: `meta${c.last_error ? " err" : ""}`, text: c.last_error ? `Último envío fallido: ${c.last_error}`
        : c.last_ok ? `Último aviso: ${new Date(c.last_ok * 1000).toLocaleString()}` : `Añadido el ${fmtDate(c.created_at)}` })),
    h("button", { class: "btn sm", onClick: async (e) => {
      const b = e.currentTarget; b.disabled = true;
      try { await api("POST", `/api/alerts/channels/${c.id}/test`); toast("Aviso de prueba enviado"); } catch (err) { toast(err.message, "err"); }
      st = await api("GET", "/api/alerts"); draw();
    } }, "Probar"),
    h("button", { class: "btn ghost icon", title: "Quitar", onClick: async () => {
      try { st = await api("DELETE", `/api/alerts/channels/${c.id}`); toast("Canal eliminado"); draw(); } catch (e) { toast(e.message, "err"); }
    } }, icon("trash")));

  const draw = () => {
    const a = st.available;
    const pushProblem = pushSupport();
    const prefs = st.prefs;
    fill(body,
      h("div", { class: "card" },
        h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Dónde recibir los avisos" }),
          h("div", { class: "note", text: "Puedes usar varios a la vez. Cada persona configura los suyos." }))),
        st.channels.length ? h("div", { class: "blocked-list" }, st.channels.map(channelRow))
          : h("p", { class: "note", style: { marginTop: 0 }, text: "Todavía no has añadido ningún canal." }),
        h("div", { class: "cell-flex", style: { flexWrap: "wrap", marginTop: "14px" } },
          h("button", { class: "btn", disabled: Boolean(pushProblem), title: pushProblem, onClick: async (e) => {
            const b = e.currentTarget; b.disabled = true;
            try { st = await enablePush(a.push_key); toast("Notificaciones activadas en este dispositivo"); } catch (err) { toast(err.message, "err"); }
            draw();
          } }, icon("bell"), "Notificaciones en este dispositivo"),
          a.telegram ? h("button", { class: "btn", onClick: connectTelegram }, icon("send"), "Conectar Telegram") : null,
          a.email ? h("button", { class: "btn", onClick: addEmail }, icon("mail"), "Añadir email") : null),
        pushProblem ? h("p", { class: "help", text: pushProblem }) : null,
        !a.telegram && !a.email && role !== "admin" ? h("p", { class: "help", text: "Telegram y email aparecerán aquí cuando tu proveedor los active." }) : null,
        !a.telegram && !a.email && role === "admin" ? h("p", { class: "help" }, "Para Telegram y email, configúralos en ", h("a", { href: "#/settings", text: "Ajustes › Avisos" }), ".") : null),
      h("div", { class: "card" },
        h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Qué avisar" }),
          h("div", { class: "note", text: `Un dispositivo vigilado se considera caído tras ${st.delay_min} min sin conectar; también avisa cuando vuelve.` }))),
        h("div", { class: "grid", style: { gap: "14px" } },
          role === "admin" ? [
            h("label", { class: "switch" }, h("input", { type: "checkbox", checked: prefs.devices_all, onChange: (e) => savePrefs({ devices_all: e.target.checked }) }),
              h("span", { class: "track" }), h("span", { text: "Dispositivos vigilados de todos los clientes" })),
            h("label", { class: "switch" }, h("input", { type: "checkbox", checked: prefs.backup, onChange: (e) => savePrefs({ backup: e.target.checked }) }),
              h("span", { class: "track" }), h("span", { text: "Copias fallidas, salidas por país caídas y actualizaciones del servidor" })),
            h("label", { class: "switch" }, h("input", { type: "checkbox", checked: prefs.server, onChange: (e) => savePrefs({ server: e.target.checked }) }),
              h("span", { class: "track" }), h("span", { text: "Servidor: disco casi lleno, memoria o CPU altas" })),
            h("label", { class: "switch" }, h("input", { type: "checkbox", checked: prefs.billing, onChange: (e) => savePrefs({ billing: e.target.checked }) }),
              h("span", { class: "track" }), h("span", { text: "Pagos: nuevas suscripciones, cancelaciones y cobros fallidos" })),
          ] : h("label", { class: "switch" }, h("input", { type: "checkbox", checked: prefs.devices, onChange: (e) => savePrefs({ devices: e.target.checked }) }),
            h("span", { class: "track" }), h("span", { text: role === "member" ? "Mis dispositivos vigilados" : "Dispositivos vigilados de mi red" })))),
      role === "admin" ? null : h("div", { class: "card" },
        h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Dispositivos vigilados" }),
          h("div", { class: "note", text: "Los routers se vigilan por defecto. Para un dispositivo que se desconecta a menudo (un móvil), mejor no." }))),
        watching === null ? spinnerBlock() : watching.length ? h("div", { class: "blocked-list" }, watching.map((d) => h("div", { class: "blocked-row" },
          h("span", { class: `dot ${d.online ? "on" : ""}` }),
          h("div", { class: "grow" }, h("div", { class: "name", text: d.name }), h("div", { class: "meta", text: d.online ? "En línea" : "Desconectado" })),
          h("label", { class: "switch", title: "Avisar si se desconecta" }, h("input", { type: "checkbox", checked: d.monitor, onChange: async (e) => {
            try { await api("PATCH", `/api/devices/${d.id}`, { monitor: e.target.checked }); d.monitor = e.target.checked; toast(d.monitor ? `Vigilando ${d.name}` : `${d.name} ya no se vigila`); }
            catch (err) { e.target.checked = !e.target.checked; toast(err.message, "err"); }
          } }), h("span", { class: "track" })))))
          : h("p", { class: "note", style: { margin: 0 }, text: "Aún no hay dispositivos." })),
    );
  };
  fill(main, pageHead("Avisos", "Entérate al momento si un router o dispositivo importante se desconecta"), body);
  draw();
  loadDevices();
}
const LINK_POLL_MS = 15 * 60 * 1000;

function exitInstallModal(name, info) {
  const m = modal({
    title: `Instalar la salida «${name}»`,
    wide: true,
    body: [
      h("ol", { class: "steps" },
        h("li", { text: "Contrata un VPS en ese país (Debian 11+ o Ubuntu 20.04+, 1 CPU y 512 MB bastan) y entra por SSH." }),
        h("li", null, "Si tu proveedor tiene firewall propio, abre el puerto ", h("b", { text: `${info.port}/UDP` }), "."),
        h("li", { text: "Ejecuta este comando como root:" })),
      h("pre", { class: "conf", text: info.command }),
      h("div", { class: "cell-flex" }, h("button", { class: "btn primary", onClick: () => copyText(info.command, "Comando copiado") }, icon("copy"), "Copiar comando")),
      h("p", { class: "note", style: { margin: 0 } }, icon("shield"), " El comando contiene la clave privada del túnel: no lo compartas. En menos de un minuto la salida aparecerá «Conectada»."),
    ],
    actions: [h("button", { class: "btn", onClick: () => m.close() }, "Cerrar")],
  });
  m.box.querySelectorAll(".note > svg").forEach((svg) => Object.assign(svg.style, { width: "14px", height: "14px", verticalAlign: "-2px" }));
}

function exitsCard() {
  const card = h("div", { class: "card" }, spinnerBlock());
  let data = null;
  const reload = async () => { data = await api("GET", "/api/admin/exits"); draw(); };
  const run = async (fn, msg) => { try { await fn(); toast(msg); await reload(); } catch (e) { toast(e.message, "err"); } };
  const exitModal = (e) => {
    let kind = e ? e.kind : "ip";
    const serverFields = [
      field("IP pública o nombre del VPS", input({ name: "host", value: e ? e.host : "", class: "input mono", autocapitalize: "off", spellcheck: "false", placeholder: "203.0.113.50" })),
      field("Puerto UDP", input({ name: "port", type: "number", min: "1024", max: "65535", value: String(e && e.port ? e.port : 51821) })),
    ];
    const ipFields = [
      h("div", { class: "full" }, field("IP adicional", input({ name: "address", value: e ? e.address || "" : "", class: "input mono", inputmode: "decimal", placeholder: "51.210.10.20" }),
        "En OVH: Bare Metal Cloud › IP › Contratar IP adicional, elige el país y asígnala a este VPS. El panel la configura sola en el servidor.")),
    ];
    const toggle = () => {
      serverFields.forEach((f) => { f.hidden = kind !== "server"; });
      ipFields.forEach((f) => { f.hidden = kind !== "ip"; });
    };
    const kindSel = e ? null : h("div", { class: "full" }, h("div", { class: "segmented" }, [["ip", "IP adicional (OVH…)"], ["server", "Servidor en otro país"]].map(([k, l]) =>
      h("label", null, h("input", { type: "radio", name: "kind", value: k, checked: k === kind, onChange: () => { kind = k; toggle(); } }), h("span", { text: l })))),
      h("div", { class: "help", text: "IP adicional: sin otro servidor; las webs ven ese país según su geolocalización. Servidor: presencia real en el país (latencia local)." }));
    formModal({
      title: e ? `Editar ${e.name}` : "Añadir salida",
      submitLabel: e ? "Guardar" : "Añadir",
      fields: [
        kindSel,
        field("Nombre", input({ name: "name", required: true, maxlength: "40", value: e ? e.name : "", placeholder: "Francia, Nueva York…" })),
        field("País", countrySelect("country", e ? e.country : "")),
        ...ipFields, ...serverFields,
      ],
      onSubmit: async (fd) => {
        const body = { name: fd.get("name"), country: fd.get("country") };
        if (kind === "ip") Object.assign(body, e ? { host: fd.get("address").trim() } : { kind: "ip", address: fd.get("address").trim() });
        else Object.assign(body, { host: fd.get("host").trim(), port: Number(fd.get("port")) });
        if (e) { await api("PATCH", `/api/admin/exits/${e.id}`, body); toast("Salida actualizada"); reload(); return; }
        const r = await api("POST", "/api/admin/exits", body);
        reload();
        if (kind === "server") setTimeout(() => exitInstallModal(r.name, r), 50);
        else toast(`IP ${r.address} añadida`);
      },
    });
    toggle();
  };
  const mainModal = () => formModal({
    title: "Servidor principal",
    fields: [field("Nombre", input({ name: "name", required: true, maxlength: "40", value: data.main.name })), field("País", countrySelect("country", data.main.country))],
    onSubmit: async (fd) => { await api("PUT", "/api/admin/main-location", { name: fd.get("name"), country: fd.get("country") }); toast("Guardado"); reload(); },
  });
  const draw = () => {
    fill(card,
      h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Salidas por país" }),
        h("div", { class: "note", text: "IPs de otros países (p. ej. IPs adicionales de OVH) o servidores en otros países por los que tus clientes pueden navegar. Los dispositivos siguen conectados a este servidor: no hay que reconfigurar nada." })),
        h("button", { class: "btn primary", onClick: () => exitModal(null) }, icon("plus"), "Añadir salida")),
      h("div", { class: "blocked-list" },
        h("div", { class: "blocked-row" }, h("span", { class: "flag", text: flag(data.main.country) }),
          h("div", { class: "grow" }, h("div", { class: "name", text: data.main.name }), h("div", { class: "meta", text: "Este servidor · salida por defecto" })),
          h("button", { class: "btn sm", onClick: mainModal }, "Editar")),
        data.exits.map((e) => h("div", { class: "blocked-row" }, h("span", { class: "flag", text: flag(e.country) }),
          h("div", { class: "grow" },
            h("div", { class: "name" }, e.name, " ", h("span", { class: `badge ${!e.enabled ? "off" : e.online ? "ok" : "warn"}`,
              text: !e.enabled ? "Desactivada" : e.kind === "ip" ? (e.online ? "Activa" : "Pendiente de aplicar")
                : e.online ? "Conectada" : e.up ? "Sin respuesta" : "Pendiente de instalar" })),
            h("div", { class: "meta mono", text: e.kind === "ip" ? [`IP adicional ${e.address}`, `${e.devices} disp.`].join(" · ")
              : [`${e.host}:${e.port}`, `${e.devices} disp.`, e.handshake ? `último contacto ${ago(e.handshake)}` : null,
                e.rx + e.tx ? `${fmtBytes(e.rx + e.tx)}` : null, e.failover ? null : "sin respaldo"].filter(Boolean).join(" · ") })),
          e.kind === "server" ? h("button", { class: "btn sm", onClick: async () => { try { exitInstallModal(e.name, await api("GET", `/api/admin/exits/${e.id}/install`)); } catch (err) { toast(err.message, "err"); } } }, "Instalar") : null,
          h("button", { class: "btn ghost icon", title: "Editar", onClick: () => exitModal(e) }, icon("edit")),
          e.kind === "ip" ? null : h("button", { class: "btn ghost icon", title: e.failover ? "Respaldo activado: si cae, sus dispositivos salen por el principal (pulsa para desactivarlo)" : "Sin respaldo: si cae, sus dispositivos se quedan sin Internet (pulsa para activarlo)",
            onClick: () => run(() => api("PATCH", `/api/admin/exits/${e.id}`, { failover: !e.failover }), e.failover ? "Respaldo desactivado (modo «sin fugas»)" : "Respaldo activado") }, icon("shield")),
          h("button", { class: "btn ghost icon", title: e.enabled ? "Desactivar" : "Activar", onClick: () =>
            run(() => api("PATCH", `/api/admin/exits/${e.id}`, { enabled: !e.enabled }), e.enabled ? "Salida desactivada" : "Salida activada") }, icon("power")),
          h("button", { class: "btn ghost icon", title: "Eliminar", onClick: async () => {
            if (await confirmDialog({ title: "Eliminar salida", message: `Sus ${e.devices} dispositivos volverán a salir por el servidor principal.`, confirmLabel: "Eliminar" })) {
              run(() => api("DELETE", `/api/admin/exits/${e.id}`), "Salida eliminada");
            }
          } }, icon("trash"))))),
      data.exits.length ? null : h("p", { class: "help", text: "Lo más sencillo: contrata IPs adicionales de otros países para este VPS y añádelas aquí." }));
  };
  reload().catch((e) => fill(card, h("p", { class: "note", text: e.message })));
  return card;
}

function alertsConfigCard() {
  const card = h("div", { class: "card" }, spinnerBlock());
  let cfg = null;
  const save = async (patch, msg) => {
    try { cfg = await api("PUT", "/api/admin/alerts-config", patch); toast(msg); draw(); } catch (e) { toast(e.message, "err"); }
  };
  const smtpModal = () => {
    const s = cfg.smtp;
    formModal({
      title: "Servidor de correo (SMTP)",
      fields: [
        h("p", { class: "note full", style: { margin: 0 }, text: "El de tu proveedor de correo (Gmail con contraseña de aplicación, Brevo, Mailgun, tu hosting…)." }),
        field("Servidor", input({ name: "smtp_host", required: true, value: s.host, placeholder: "smtp.tudominio.com", class: "input mono", autocapitalize: "off" })),
        field("Puerto", input({ name: "smtp_port", type: "number", required: true, value: String(s.port), min: "1", max: "65535" })),
        h("div", { class: "full" }, field("Seguridad", h("div", { class: "segmented" }, [["starttls", "STARTTLS (587)"], ["ssl", "SSL/TLS (465)"], ["none", "Ninguna"]].map(([k, l]) =>
          h("label", null, h("input", { type: "radio", name: "smtp_security", value: k, checked: s.security === k }), h("span", { text: l })))))),
        field("Usuario", input({ name: "smtp_user", value: s.user, autocomplete: "off", autocapitalize: "off" })),
        field("Contraseña", input({ name: "smtp_password", type: "password", autocomplete: "new-password", placeholder: s.password_set ? "(guardada)" : "" }),
          s.password_set ? "Déjala vacía para conservarla." : null),
        h("div", { class: "full" }, field("Remitente", input({ name: "smtp_from", required: true, value: s.from, placeholder: "Avisos VPN <avisos@tudominio.com>" }))),
      ],
      onSubmit: async (fd) => {
        cfg = await api("PUT", "/api/admin/alerts-config", { smtp_host: fd.get("smtp_host"), smtp_port: Number(fd.get("smtp_port")),
          smtp_security: fd.get("smtp_security"), smtp_user: fd.get("smtp_user"), smtp_password: fd.get("smtp_password") || null, smtp_from: fd.get("smtp_from") });
        toast("Correo configurado. Prueba enviando un aviso desde Avisos.");
        draw();
      },
    });
  };
  const telegramModal = () => formModal({
    title: "Bot de Telegram",
    fields: [
      h("ol", { class: "steps full" },
        h("li", null, "En Telegram, abre ", h("a", { href: "https://t.me/BotFather", target: "_blank", rel: "noopener", text: "@BotFather" }), " y envía ", h("code", { text: "/newbot" }), "."),
        h("li", { text: "Elige un nombre (p. ej. «Avisos de Mi VPN») y un usuario acabado en bot." }),
        h("li", { text: "Copia el token que te da y pégalo aquí." })),
      h("div", { class: "full" }, field("Token", input({ name: "token", required: true, class: "input mono", placeholder: "123456789:AA…", autocomplete: "off", autocapitalize: "off", spellcheck: "false" }))),
    ],
    onSubmit: async (fd) => { cfg = await api("PUT", "/api/admin/alerts-config", { telegram_token: fd.get("token").trim() }); toast("Bot de Telegram conectado"); draw(); },
  });
  const draw = () => {
    const delays = [2, 5, 10, 15, 30, 60].map((n) => h("option", { value: String(n), selected: n === cfg.delay_min, text: `${n} min` }));
    fill(card,
      h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Avisos" }),
        h("div", { class: "note", text: "Canales que podrán usar tú y tus clientes para recibir avisos. Las notificaciones push funcionan siempre (con HTTPS)." }))),
      h("div", { class: "grid", style: { gap: "14px" } },
        h("div", { class: "blocked-row" }, h("span", { class: "channel-icon" }, icon("send")),
          h("div", { class: "grow" }, h("div", { class: "name", text: "Telegram" }),
            h("div", { class: "meta", text: cfg.telegram.configured ? `Bot @${cfg.telegram.bot}` : "Sin configurar" })),
          h("button", { class: "btn sm", onClick: telegramModal }, cfg.telegram.configured ? "Cambiar" : "Configurar"),
          cfg.telegram.configured ? h("button", { class: "btn ghost icon", title: "Quitar", onClick: () => save({ telegram_token: "" }, "Telegram desactivado") }, icon("trash")) : null),
        h("div", { class: "blocked-row" }, h("span", { class: "channel-icon" }, icon("mail")),
          h("div", { class: "grow" }, h("div", { class: "name", text: "Email" }),
            h("div", { class: "meta", text: cfg.smtp.host ? `${cfg.smtp.host}:${cfg.smtp.port} · ${cfg.smtp.from}` : "Sin configurar" })),
          h("button", { class: "btn sm", onClick: smtpModal }, cfg.smtp.host ? "Cambiar" : "Configurar")),
        h("label", { class: "inline-field" }, "Considerar caído un dispositivo tras",
          h("select", { class: "input", onChange: (e) => save({ delay_min: Number(e.target.value) }, "Guardado") }, delays), "sin conectar")));
  };
  api("GET", "/api/admin/alerts-config").then((d) => { cfg = d; draw(); }).catch((e) => fill(card, h("p", { class: "note", text: e.message })));
  return card;
}

/* ------------------------------------------------------------------ usuarios de un cliente */
async function memberHomeView(main) {
  const load = async () => {
    const devices = await api("GET", "/api/devices");
    fill(main,
      pageHead(`Hola, ${state.me.name}`, `Tus dispositivos en la red privada de ${state.me.tenant_name}`),
      devicesCard(devices, { tenantId: state.me.tenant_id, max: state.me.max_devices, onChange: load }));
  };
  await load();
  every(load);
}

function shareOrCopy(url, title) {
  if (navigator.share && (isIOS() || isStandalone() || /Android/.test(navigator.userAgent))) {
    navigator.share({ title, url }).catch(() => {});
  } else copyText(url, "Enlace copiado");
}

function linkBox(url, title, note) {
  return h("div", { class: "grid", style: { gap: "10px" } },
    h("div", { class: "input-group" }, input({ value: url, readonly: true, class: "input mono", onFocus: (e) => e.target.select() }),
      h("button", { class: "btn icon", type: "button", title: "Copiar", onClick: () => copyText(url, "Enlace copiado") }, icon("copy"))),
    h("div", { class: "cell-flex", style: { flexWrap: "wrap" } },
      h("button", { class: "btn primary", type: "button", onClick: () => shareOrCopy(url, title) }, icon("share"), "Compartir"),
      h("a", { class: "btn", href: `https://wa.me/?text=${encodeURIComponent(`${title}: ${url}`)}`, target: "_blank", rel: "noopener" }, "WhatsApp"),
      h("a", { class: "btn", href: `mailto:?subject=${encodeURIComponent(title)}&body=${encodeURIComponent(url)}` }, icon("mail"), "Email")),
    note ? h("p", { class: "note", style: { margin: 0 }, text: note }) : null);
}

async function installLinkModal(d) {
  const box = h("div", null, spinnerBlock());
  const draw = (st, url) => {
    const hours = [[1, "1 hora"], [24, "24 horas"], [168, "7 días"]];
    let chosen = 24;
    fill(box,
      h("p", { class: "note", style: { marginTop: 0 }, text: `Una página con el QR y el archivo de ${d.name}, para quien lo vaya a instalar. No necesita cuenta. Cualquiera con el enlace puede usar esta configuración: compártelo sólo con esa persona.` }),
      url ? linkBox(url, `Configuración VPN de ${d.name}`, `Caduca el ${new Date(st.expires_at * 1000).toLocaleString()}.`) : null,
      !url && st.active ? h("div", { class: "domain-status" },
        checkLine(true, `Hay un enlace activo hasta el ${new Date(st.expires_at * 1000).toLocaleString()} · abierto ${st.views} ${st.views === 1 ? "vez" : "veces"}`, ""),
        h("p", { class: "note", style: { margin: 0 }, text: "Por seguridad no se puede volver a mostrar: crea uno nuevo (el anterior dejará de funcionar) o anúlalo." })) : null,
      h("div", { class: "cell-flex", style: { flexWrap: "wrap", marginTop: "12px" } },
        h("div", { class: "segmented compact" }, hours.map(([n, label]) => h("label", null,
          h("input", { type: "radio", name: "link-hours", checked: n === chosen, onChange: () => { chosen = n; } }), h("span", { text: label })))),
        h("button", { class: "btn", onClick: async () => {
          try { const r = await api("POST", `/api/devices/${d.id}/link`, { hours: chosen }); draw(r, r.url); } catch (e) { toast(e.message, "err"); }
        } }, icon("plus"), url || st.active ? "Crear otro" : "Crear enlace"),
        st.active ? h("button", { class: "btn ghost", onClick: async () => {
          try { draw(await api("DELETE", `/api/devices/${d.id}/link`), null); toast("Enlace anulado"); } catch (e) { toast(e.message, "err"); }
        } }, icon("trash"), "Anular") : null));
  };
  const m = modal({ title: `Enlace de instalación · ${d.name}`, wide: true, body: box,
    actions: [h("button", { class: "btn", onClick: () => m.close() }, "Cerrar")] });
  try { draw(await api("GET", `/api/devices/${d.id}/link`), null); } catch (e) { toast(e.message, "err"); m.close(); }
}

async function usersView(main, tenantId) {
  const isAdmin = state.me.role === "admin";
  const qs = isAdmin ? `?tenant_id=${tenantId}` : "";
  const tenant = isAdmin ? await api("GET", `/api/admin/tenants/${tenantId}`) : { name: state.me.name };
  let data = await api("GET", `/api/members${qs}`);
  const body = h("div");
  const reload = async () => { data = await api("GET", `/api/members${qs}`); draw(); };
  const run = async (fn, msg) => { try { await fn(); toast(msg); await reload(); } catch (e) { toast(e.message, "err"); } };
  const withTenant = (b) => (isAdmin ? { ...b, tenant_id: tenantId } : b);
  const canCreateField = (checked) => h("div", { class: "full field" }, switchEl("can_create", checked, "Puede añadir sus propios dispositivos"),
    h("div", { class: "help", text: "Si no, sólo verá los que le asignes tú." }));

  const invite = () => formModal({
    title: "Invitar a un usuario",
    submitLabel: "Crear invitación",
    fields: [h("div", { class: "full" }, field("Nombre", input({ name: "name", required: true, maxlength: "64", placeholder: "Ana López" }))), canCreateField(true)],
    onSubmit: async (fd) => {
      const r = await api("POST", "/api/members/invite", withTenant({ name: fd.get("name"), can_create: fd.get("can_create") === "on" }));
      reload();
      setTimeout(() => {
        const m = modal({ title: "Invitación creada", wide: true,
          body: linkBox(r.url, `Invitación a la VPN de ${tenant.name}`, `Enlace de un solo uso, válido 7 días. Con él, ${fd.get("name")} elige su usuario y contraseña.`),
          actions: [h("button", { class: "btn", onClick: () => m.close() }, "Hecho")] });
      }, 50);
    },
  });
  const create = () => formModal({
    title: "Crear usuario",
    submitLabel: "Crear",
    fields: [
      h("div", { class: "full" }, field("Nombre", input({ name: "name", required: true, maxlength: "64" }))),
      h("div", { class: "full" }, field("Usuario", input({ name: "username", required: true, pattern: "[A-Za-z0-9][A-Za-z0-9._\\-]{2,31}", autocapitalize: "off", spellcheck: "false" }))),
      passwordField("password", "Contraseña temporal", "Se le pedirá cambiarla al entrar."),
      canCreateField(true),
    ],
    onSubmit: async (fd) => {
      await api("POST", "/api/members", withTenant({ name: fd.get("name"), username: fd.get("username"), password: fd.get("password"),
        can_create: fd.get("can_create") === "on" }));
      reload();
      setTimeout(() => credentialsModal(fd.get("name"), fd.get("username"), fd.get("password"), tenant.name), 50);
    },
  });
  const edit = (m) => formModal({
    title: `Editar ${m.name}`,
    fields: [h("div", { class: "full" }, field("Nombre", input({ name: "name", required: true, maxlength: "64", value: m.name }))), canCreateField(m.can_create)],
    onSubmit: async (fd) => { await api("PATCH", `/api/members/${m.id}`, { name: fd.get("name"), can_create: fd.get("can_create") === "on" }); toast("Usuario actualizado"); reload(); },
  });
  const resetPassword = (m) => formModal({
    title: `Nueva contraseña para ${m.name}`,
    fields: [passwordField("password", "Contraseña temporal", "Se le pedirá cambiarla al entrar. Se cerrarán sus sesiones abiertas.")],
    onSubmit: async (fd) => {
      await api("PATCH", `/api/members/${m.id}`, { password: fd.get("password") });
      reload();
      setTimeout(() => credentialsModal(m.name, m.username, fd.get("password"), tenant.name), 50);
    },
  });

  const draw = () => {
    fill(body,
      h("div", { class: "card" },
        h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Usuarios" }),
          h("div", { class: "note", text: "Cada usuario entra con su propia cuenta y sólo ve sus dispositivos, su actividad y sus avisos." }))),
        data.members.length ? h("div", { class: "table-wrap" }, h("table", { class: "cards" },
          h("thead", null, h("tr", null, h("th", { text: "Usuario" }), h("th", { text: "Dispositivos" }), h("th", { class: "hide-sm", text: "Último acceso" }), h("th"))),
          h("tbody", null, data.members.map((m) => h("tr", null,
            h("td", { class: "primary" }, h("div", { class: "cell-flex" }, h("span", { class: `dot ${m.enabled ? "on" : "dis"}` }),
              h("div", null, h("div", { class: "name", text: m.name }),
                h("div", { class: "meta", text: [m.username, m.enabled ? null : "desactivado", m.must_change ? "pendiente de primer acceso" : null,
                  m.can_create ? null : "sin altas propias"].filter(Boolean).join(" · ") })))),
            h("td", { "data-label": "Dispositivos", text: String(m.devices) }),
            h("td", { class: "hide-sm", "data-label": "Último acceso", text: m.last_login ? ago(m.last_login) : "nunca" }),
            h("td", { class: "actions aside" },
              h("button", { class: "btn ghost icon", title: "Editar", onClick: () => edit(m) }, icon("edit")),
              h("button", { class: "btn ghost icon", title: "Nueva contraseña", onClick: () => resetPassword(m) }, icon("key")),
              h("button", { class: "btn ghost icon", title: m.enabled ? "Desactivar" : "Activar", onClick: () =>
                run(() => api("PATCH", `/api/members/${m.id}`, { enabled: !m.enabled }), m.enabled ? "Usuario desactivado" : "Usuario activado") }, icon("power")),
              h("button", { class: "btn ghost icon", title: "Eliminar", onClick: async () => {
                if (await confirmDialog({ title: "Eliminar usuario", message: `${m.name} ya no podrá entrar. Sus ${m.devices} dispositivos se quedan en la red sin asignar (puedes asignarlos a otro usuario o eliminarlos).`, confirmLabel: "Eliminar" })) {
                  run(() => api("DELETE", `/api/members/${m.id}`), "Usuario eliminado");
                }
              } }, icon("trash")))))))) : h("div", { class: "empty" }, icon("users"), h("h2", { text: "Sólo tú, de momento" }),
          h("p", { text: "Invita a tus empleados o familiares: cada uno tendrá su cuenta y sus dispositivos, y tú lo verás todo." }),
          h("button", { class: "btn primary", onClick: invite }, icon("send"), "Invitar"))),
      data.invites.length ? h("div", { class: "card" }, h("h3", { text: "Invitaciones pendientes" }),
        h("div", { class: "blocked-list", style: { marginTop: "10px" } }, data.invites.map((i) => h("div", { class: "blocked-row" },
          h("div", { class: "grow" }, h("div", { class: "name", text: i.name }), h("div", { class: "meta", text: `Caduca el ${new Date(i.expires_at * 1000).toLocaleDateString()}` })),
          h("button", { class: "btn ghost icon", title: "Anular", onClick: () => run(() => api("DELETE", `/api/invites/${i.id}`), "Invitación anulada") }, icon("trash")))))) : null,
    );
  };
  const crumbs = isAdmin ? [h("a", { href: "#/clients", text: "Clientes" }), " / ", h("a", { href: `#/clients/${tenantId}`, text: tenant.name }), " / Usuarios"] : null;
  fill(main, pageHead("Usuarios", `Personas con acceso a la red de ${tenant.name}`, h("div", { class: "cell-flex" },
    h("button", { class: "btn", onClick: create }, icon("plus"), "Crear"),
    h("button", { class: "btn primary", onClick: invite }, icon("send"), "Invitar")), crumbs), body);
  draw();
}

/* ------------------------------------------------------------------ páginas públicas */
function publicShell(...children) {
  $app.className = "";
  fill($app, h("div", { class: "auth" }, h("div", { class: "auth-card wide" }, brand(), ...children)));
}

async function inviteView(token) {
  let info;
  try { info = await api("GET", `/api/invite/${encodeURIComponent(token)}`); }
  catch (e) { return publicShell(h("p", { class: "lead", text: e.message }), h("a", { class: "btn block", href: "#/" }, "Ir al inicio")); }
  const err = h("div", { class: "help", style: { color: "var(--danger)", minHeight: "18px" } });
  const btn = h("button", { class: "btn primary block", type: "submit" }, "Crear mi cuenta");
  const form = h("form", { onSubmit: async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    err.textContent = "";
    if (fd.get("password") !== fd.get("repeat")) { err.textContent = "Las contraseñas no coinciden"; return; }
    btn.disabled = true;
    try {
      await api("POST", `/api/invite/${encodeURIComponent(token)}`, { username: fd.get("username"), password: fd.get("password") });
      state.me = await api("GET", "/api/me");
      state.passkeyChecked = false;
      history.replaceState(null, "", "#/");
      render();
      toast(`Bienvenido/a, ${state.me.name}`);
    } catch (ex) { err.textContent = ex.message; } finally { btn.disabled = false; }
  } },
    field("Elige tu usuario", input({ name: "username", required: true, pattern: "[A-Za-z0-9][A-Za-z0-9._\\-]{2,31}", autocomplete: "username",
      autocapitalize: "none", spellcheck: "false", placeholder: info.name.split(" ")[0].toLowerCase().normalize("NFD").replace(/[^a-z0-9]/g, "") })),
    field("Contraseña", input({ name: "password", type: "password", required: true, minlength: "8", autocomplete: "new-password" })),
    field("Repítela", input({ name: "repeat", type: "password", required: true, minlength: "8", autocomplete: "new-password" })),
    err, btn);
  publicShell(h("p", { class: "lead" }, "Hola, ", h("b", { text: info.name }), `. Te han invitado a la red privada de `, h("b", { text: info.tenant }), "."), form);
}

async function sharedConfigView(token) {
  let info;
  try { info = await api("GET", `/api/get/${encodeURIComponent(token)}`); }
  catch (e) { return publicShell(h("p", { class: "lead", text: e.message })); }
  const stores = [["App Store", "https://apps.apple.com/app/wireguard/id1441195209"], ["Google Play", "https://play.google.com/store/apps/details?id=com.wireguard.android"],
    ["Windows / Mac / Linux", "https://www.wireguard.com/install/"]];
  publicShell(
    h("p", { class: "lead" }, "Configuración VPN de ", h("b", { text: info.device }), ` (${info.tenant})`),
    h("ol", { class: "steps" },
      h("li", null, "Instala la app WireGuard: ", ...stores.flatMap(([n, u], i) => [i ? " · " : "", h("a", { href: u, target: "_blank", rel: "noopener", text: n })]), "."),
      h("li", { text: "En el móvil: «Añadir túnel» › «Crear desde código QR» y escanea este código (desde otra pantalla)." }),
      h("li", { text: "En este mismo dispositivo u ordenador: descarga el archivo e impórtalo en la app." })),
    h("div", { class: "qr-box" }, h("img", { src: `/api/get/${encodeURIComponent(token)}/qr.svg`, alt: "Código QR de la configuración", width: "260", height: "260" })),
    h("button", { class: "btn primary block", onClick: () => saveConfig({ name: info.filename.replace(/\.conf$/, ""), id: 0 }, info.conf) }, icon("download"), "Descargar archivo"),
    h("p", { class: "note", style: { textAlign: "center" }, text: `Enlace válido hasta el ${new Date(info.expires_at * 1000).toLocaleString()}. Contiene una clave privada: no lo compartas.` }));
}

/* ------------------------------------------------------------------ facturación */
const STATUS_LABEL = { active: ["ok", "Activa"], trialing: ["accent", "En prueba"], past_due: ["warn", "Pago pendiente"],
  unpaid: ["off", "Impagada"], incomplete: ["warn", "Pago incompleto"], canceled: ["off", "Cancelada"], pending: ["warn", "Pendiente de pago"],
  manual: ["accent", "Manual"], free: ["ok", "Gratuita"], none: ["", "Sin plan"], incomplete_expired: ["off", "Caducada"] };
function statusBadge(st) {
  const [cls, label] = STATUS_LABEL[st] || ["", st];
  return h("span", { class: `badge ${cls}`, text: label });
}
function fmtDay(ts) { return ts ? new Date(ts * 1000).toLocaleDateString("es-ES", { day: "numeric", month: "long", year: "numeric" }) : ""; }
function planFeatures(p) {
  return [
    `${p.max_devices} dispositivos`,
    p.max_members ? `${p.max_members} usuarios` : null,
    p.max_forwards ? `${p.max_forwards} puertos abiertos` : null,
    p.max_services ? `${p.max_services} servicios con HTTPS` : null,
    p.allow_exits ? "Salidas por país" : null,
    "Filtros de navegación y DNS propio",
    p.trial_days ? `${p.trial_days} días de prueba gratis` : null,
  ].filter(Boolean);
}
function planCard(p, { current = false, action = null } = {}) {
  return h("div", { class: `card plan-card${current ? " current" : ""}` },
    h("div", { class: "plan-name", text: p.name }),
    h("div", { class: "plan-price" }, p.price, h("span", { text: p.interval === "year" ? " / año" : " / mes" })),
    p.description ? h("p", { class: "note", text: p.description }) : null,
    h("ul", { class: "plan-features" }, planFeatures(p).map((f) => h("li", null, icon("check"), f))),
    current ? h("div", { class: "badge ok plan-current", text: "Tu plan actual" }) : action);
}

let billingCache = null;
function billingBanner() {
  const box = h("div");
  api("GET", "/api/billing").then((b) => {
    billingCache = b;
    if (b.status === "past_due" || b.status === "unpaid" || b.status === "incomplete") {
      fill(box, h("div", { class: "banner warn" }, icon("alert"),
        h("span", null, "No hemos podido cobrar tu suscripción. ", b.suspend_at ? `Actualiza tu forma de pago antes del ${fmtDay(b.suspend_at)} para evitar la suspensión. ` : "",
          h("a", { href: "#/plan", text: "Revisar el pago" }))));
    } else if (b.cancel_at_period_end && b.period_end) {
      fill(box, h("div", { class: "banner" }, icon("alert"), `Tu suscripción termina el ${fmtDay(b.period_end)}. `, h("a", { href: "#/plan", text: "Reactivar" })));
    }
  }).catch(() => {});
  return box;
}

async function openStripe(path, body) {
  const r = await api("POST", path, body);
  if (r.url) { location.href = r.url; return null; }
  return r;
}

async function planView(main, tenantId) {
  const isAdmin = state.me.role === "admin";
  const qs = isAdmin ? `?tenant_id=${tenantId}` : "";
  let b = await api("GET", `/api/billing${qs}`);
  const tenant = isAdmin ? await api("GET", `/api/admin/tenants/${tenantId}`) : null;
  const body = h("div");
  const invoicesBox = h("div", { class: "card" }, spinnerBlock());
  if (hashParam("pago") === "ok") toast("Pago recibido: tu plan se activará en unos segundos");

  const choose = async (p, btn) => {
    const changing = b.plan && ["active", "trialing", "past_due", "unpaid"].includes(b.status);
    if (changing && !(await confirmDialog({ title: `Cambiar a ${p.name}`, message: `Pasarás a pagar ${p.price}${p.interval === "year" ? " al año" : " al mes"}. La diferencia de este periodo se ajusta en tu próxima factura.`, confirmLabel: "Cambiar de plan", danger: false }))) return;
    btn.disabled = true;
    try {
      const r = await openStripe(`/api/billing/checkout${qs}`, { plan_id: p.id });
      if (r && r.changed) { b = r; toast(`Ahora tienes el plan ${p.name}`); state.me = await api("GET", "/api/me"); draw(); }
    } catch (e) { toast(e.message, "err"); btn.disabled = false; }
  };
  const usage = (label, used, max) => h("div", { class: "usage" },
    h("div", { class: "usage-head" }, h("span", { text: label }), h("span", { class: "mono", text: max ? `${used} / ${max}` : `${used}` })),
    h("div", { class: "progress" }, h("span", { style: { width: `${max ? Math.min(100, (100 * used) / max) : 0}%` } })));

  const draw = () => {
    const due = ["past_due", "unpaid", "incomplete"].includes(b.status);
    fill(body,
      b.suspended ? h("div", { class: "banner danger" }, icon("alert"), b.status === "pending"
        ? "Tu cuenta se activará en cuanto se complete el pago."
        : "Tu servicio está suspendido por falta de pago. Actualiza tu forma de pago y se reactivará al momento.") : null,
      due && !b.suspended ? h("div", { class: "banner warn" }, icon("alert"), `No hemos podido cobrar tu suscripción.${b.suspend_at ? ` Si no se resuelve antes del ${fmtDay(b.suspend_at)}, el servicio se suspenderá.` : ""}`) : null,
      h("div", { class: "grid two" },
        h("div", { class: "card" },
          h("div", { class: "card-head" }, h("div", null, h("h2", { text: b.plan ? b.plan.name : "Sin plan" }),
            h("div", { class: "cell-flex", style: { marginTop: "6px", flexWrap: "wrap" } }, statusBadge(b.status),
              b.plan ? h("span", { class: "note", text: `${b.plan.price}${b.plan.interval === "year" ? " / año" : " / mes"}` }) : null))),
          b.period_end && b.status !== "manual" ? h("p", { class: "note", text: b.cancel_at_period_end ? `Termina el ${fmtDay(b.period_end)}.`
            : b.status === "trialing" ? `Prueba gratis hasta el ${fmtDay(b.period_end)}.` : `Próxima renovación: ${fmtDay(b.period_end)}.` }) : null,
          b.status === "manual" ? h("p", { class: "note", text: "Plan asignado por tu proveedor (sin cobro automático)." }) : null,
          b.status === "free" ? h("p", { class: "note", text: "Cuenta gratuita: sin cobros." }) : null,
          !b.plan && b.status !== "free" ? h("p", { class: "note", text: b.stripe && b.plans.length ? "Elige un plan abajo para empezar. Pagas con tarjeta de forma segura con Stripe y puedes cancelar cuando quieras."
            : "Tus límites los fija tu proveedor." }) : null,
          h("div", { class: "cell-flex", style: { flexWrap: "wrap", marginTop: "12px" } },
            b.has_customer && b.stripe ? h("button", { class: "btn primary", onClick: async (e) => {
              e.currentTarget.disabled = true;
              try { await openStripe(`/api/billing/portal${qs}`); } catch (err) { toast(err.message, "err"); e.currentTarget.disabled = false; }
            } }, icon("card"), "Gestionar pago y facturas") : null,
            isAdmin && b.customer_url ? h("a", { class: "btn", href: b.customer_url, target: "_blank", rel: "noopener" }, "Ver en Stripe") : null,
            isAdmin ? h("button", { class: "btn", onClick: () => assignPlanModal(tenantId, b, async () => { b = await api("GET", `/api/billing${qs}`); draw(); }) }, icon("edit"), "Plan manual o gratuito") : null)),
        h("div", { class: "card" }, h("h3", { text: "Uso" }),
          h("div", { class: "grid", style: { gap: "12px", marginTop: "12px" } },
            usage("Dispositivos", b.usage.devices, b.limits.devices),
            usage("Usuarios", b.usage.members, b.limits.members),
            usage("Puertos abiertos", b.usage.forwards, b.limits.forwards),
            usage("Servicios con HTTPS", b.usage.services, b.limits.services),
            h("div", { class: "note", text: b.limits.exits ? "Incluye salidas por país." : "No incluye salidas por país." })))),
      b.stripe && b.plans.length ? h("div", null,
        h("h3", { style: { margin: "24px 0 12px" }, text: b.plan ? "Cambiar de plan" : "Elige tu plan" }),
        h("div", { class: "plan-grid" }, b.plans.map((p) => planCard(p, { current: b.plan && b.plan.id === p.id && !["canceled", "pending", "manual", "none"].includes(b.status),
          action: h("button", { class: "btn primary block", onClick: (e) => choose(p, e.currentTarget) },
            b.plan && ["active", "trialing", "past_due", "unpaid"].includes(b.status) ? "Cambiar a este plan" : "Contratar") })))) : null,
      invoicesBox);
  };
  const crumbs = isAdmin ? [h("a", { href: "#/clients", text: "Clientes" }), " / ", h("a", { href: `#/clients/${tenantId}`, text: tenant.name }), " / Plan"] : null;
  fill(main, pageHead(isAdmin ? "Plan y facturación" : "Tu plan", isAdmin ? `Suscripción de ${tenant.name}` : "Suscripción, uso y facturas", null, crumbs), body);
  draw();
  api("GET", `/api/billing/invoices${qs}`).then((r) => {
    if (!r.invoices.length) { invoicesBox.hidden = true; return; }
    fill(invoicesBox, h("h3", { text: "Facturas" }), h("div", { class: "blocked-list", style: { marginTop: "10px" } }, r.invoices.map((i) => h("div", { class: "blocked-row" },
      h("div", { class: "grow" }, h("div", { class: "name", text: `${i.number || i.id} · ${i.total}` }), h("div", { class: "meta", text: fmtDay(i.created) })),
      statusBadge(i.status === "paid" ? "active" : i.status === "open" ? "past_due" : "canceled"),
      i.url ? h("a", { class: "btn sm", href: i.url, target: "_blank", rel: "noopener" }, "Ver") : null,
      i.pdf ? h("a", { class: "btn ghost sm", href: i.pdf, target: "_blank", rel: "noopener" }, icon("download"), "PDF") : null))));
  }).catch(() => { invoicesBox.hidden = true; });
}

async function assignPlanModal(tenantId, b, onDone) {
  const data = await api("GET", "/api/admin/billing");
  formModal({
    title: "Plan del cliente",
    fields: [
      h("p", { class: "note full", style: { margin: 0 }, text: "Para clientes que te pagan por otros medios (transferencia, efectivo…): se aplican los límites del plan y nunca se suspende automáticamente. Si el cliente tiene suscripción en Stripe, gestiónala desde allí." }),
      h("div", { class: "full" }, field("Plan", h("select", { class: "input", name: "plan_id" },
        h("option", { value: "", text: "Sin plan (límites manuales)", selected: !b.plan }),
        data.plans.filter((p) => p.active).map((p) => h("option", { value: String(p.id), selected: b.plan && b.plan.id === p.id, text: `${p.name} · ${p.price}` }))),
        "Con plan se aplican sus límites; sin plan, los que pongas en «Editar cliente».")),
      h("div", { class: "full field" }, switchEl("free", b.status === "free", "Gratuito (proyecto propio)"),
        h("div", { class: "help", text: ["active", "trialing", "past_due", "unpaid"].includes(b.status)
          ? "Si lo marcas, se cancelará su suscripción de Stripe y no se le volverá a cobrar."
          : "Nunca se le cobra ni se suspende por pagos, y no ve planes que contratar." })),
    ],
    onSubmit: async (fd) => {
      await api("PUT", `/api/admin/tenants/${tenantId}/plan`, { plan_id: fd.get("plan_id") ? Number(fd.get("plan_id")) : null, free: fd.get("free") === "on" });
      toast(fd.get("free") === "on" ? "Cliente marcado como gratuito" : "Plan asignado");
      onDone();
    },
  });
}

function planModal(plan, onDone) {
  const num = (name, label, value, help, min = "0") => field(label, input({ name, type: "number", min, required: true, value: String(value) }), help);
  formModal({
    title: plan ? `Editar ${plan.name}` : "Nuevo plan",
    submitLabel: plan ? "Guardar" : "Crear plan",
    fields: [
      field("Nombre", input({ name: "name", required: true, maxlength: "40", value: plan ? plan.name : "", placeholder: "Básico, Pro, Empresa…" })),
      field("Precio (€)", input({ name: "price", type: "number", min: "0", step: "0.01", required: true, value: plan ? (plan.price_cents / 100).toFixed(2) : "" }),
        plan ? "Si lo cambias, los clientes actuales mantienen su precio hasta que cambien de plan." : null),
      field("Periodo", h("div", { class: "segmented" }, [["month", "Mensual"], ["year", "Anual"]].map(([k, l]) =>
        h("label", null, h("input", { type: "radio", name: "interval", value: k, checked: (plan ? plan.interval : "month") === k }), h("span", { text: l }))))),
      num("trial_days", "Días de prueba gratis", plan ? plan.trial_days : 0),
      h("div", { class: "full" }, field("Descripción", input({ name: "description", maxlength: "200", value: plan ? plan.description : "", placeholder: "Ideal para familias, pequeñas oficinas…" }))),
      num("max_devices", "Dispositivos", plan ? plan.max_devices : 5, null, "1"),
      num("max_members", "Usuarios adicionales", plan ? plan.max_members : 0),
      num("max_forwards", "Puertos abiertos", plan ? plan.max_forwards : 0),
      num("max_services", "Servicios con HTTPS", plan ? plan.max_services : 0),
      h("div", { class: "full field" }, switchEl("allow_exits", plan ? plan.allow_exits : false, "Incluye salidas por país")),
      h("div", { class: "full field" }, switchEl("public", plan ? plan.public : true, "Visible para contratar"),
        h("div", { class: "help", text: "Desactívalo para planes a medida que sólo asignas tú." })),
    ],
    onSubmit: async (fd) => {
      const body = { name: fd.get("name"), description: fd.get("description") || "", price_cents: Math.round(Number(fd.get("price")) * 100),
        interval: fd.get("interval"), trial_days: Number(fd.get("trial_days")), max_devices: Number(fd.get("max_devices")),
        max_members: Number(fd.get("max_members")), max_forwards: Number(fd.get("max_forwards")), max_services: Number(fd.get("max_services")),
        allow_exits: fd.get("allow_exits") === "on", public: fd.get("public") === "on" };
      await api(plan ? "PATCH" : "POST", plan ? `/api/admin/plans/${plan.id}` : "/api/admin/plans", body);
      toast(plan ? "Plan actualizado" : "Plan creado");
      onDone();
    },
  });
}

async function billingAdminView(main) {
  let data = await api("GET", "/api/admin/billing");
  const body = h("div");
  const reload = async () => { data = await api("GET", "/api/admin/billing"); draw(); };
  const run = async (fn, msg) => { try { data = await fn(); toast(msg); draw(); } catch (e) { toast(e.message, "err"); } };
  const draw = () => {
    const st = data.stripe;
    const keyInput = input({ placeholder: "sk_live_…", class: "input mono", autocomplete: "off", autocapitalize: "off", spellcheck: "false" });
    const signupUrl = `${location.origin}/#/signup`;
    fill(body,
      h("div", { class: "grid stats" },
        statCard("card", "Ingresos mensuales", data.stats.mrr, "suscripciones activas", true),
        statCard("users", "Activas", String(data.stats.active), `${data.stats.trialing} en prueba · ${data.stats.manual} manuales · ${data.stats.free} gratis`),
        statCard("alert", "Pago pendiente", String(data.stats.past_due), "en periodo de gracia"),
        statCard("power", "Suspendidos", String(data.stats.suspended), "por impago")),
      data.attention.length ? h("div", { class: "card" }, h("h3", { text: "Requieren atención" }),
        h("div", { class: "blocked-list", style: { marginTop: "10px" } }, data.attention.map((a) => h("div", { class: "blocked-row link", onClick: () => go(`#/plan/${a.id}`) },
          h("div", { class: "grow" }, h("div", { class: "name", text: a.name }), h("div", { class: "meta", text: [a.plan, a.past_due_since ? `sin pagar desde el ${fmtDay(a.past_due_since)}` : null].filter(Boolean).join(" · ") })),
          a.suspended ? h("span", { class: "badge off", text: "Suspendido" }) : statusBadge(a.status))))) : null,
      h("div", { class: "card" },
        h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Stripe" }),
          h("div", { class: "note", text: "Cobros con tarjeta, Apple Pay, Google Pay y SEPA. El dinero llega a tu cuenta de Stripe." })),
          st.connected ? h("span", { class: `badge ${st.live ? "ok" : "warn"}`, text: st.live ? "Modo real" : "Modo pruebas" }) : null),
        st.connected
          ? h("div", { class: "grid", style: { gap: "12px" } },
            checkLine(true, `Conectado a «${st.account}». Webhook configurado automáticamente.`, ""),
            h("div", { class: "cell-flex", style: { flexWrap: "wrap" } },
              h("a", { class: "btn", href: `https://dashboard.stripe.com/${st.live ? "" : "test/"}dashboard`, target: "_blank", rel: "noopener" }, "Abrir Stripe"),
              h("button", { class: "btn ghost", onClick: async () => {
                if (await confirmDialog({ title: "Desconectar Stripe", message: "Las suscripciones siguen en Stripe, pero el panel dejará de recibir sus pagos y cambios.", confirmLabel: "Desconectar" })) {
                  run(() => api("DELETE", "/api/admin/billing/stripe"), "Stripe desconectado");
                }
              } }, "Desconectar")))
          : h("div", { class: "grid", style: { gap: "12px" } },
            h("ol", { class: "steps" },
              h("li", null, "Crea tu cuenta en ", h("a", { href: "https://dashboard.stripe.com/register", target: "_blank", rel: "noopener", text: "stripe.com" }), " y actívala (datos de tu empresa y cuenta bancaria)."),
              h("li", { text: "Desarrolladores › Claves de API › copia la «Clave secreta» (sk_live_…; para probar, sk_test_…)." }),
              h("li", { text: "Pégala aquí. El panel crea solo el webhook y los productos de tus planes." })),
            h("div", { class: "input-group" }, keyInput, h("button", { class: "btn primary", onClick: () =>
              run(() => api("PUT", "/api/admin/billing/stripe", { secret_key: keyInput.value.trim() }), "Stripe conectado") }, "Conectar")),
            h("p", { class: "help", text: "Requiere el dominio del panel con HTTPS (Ajustes): Stripe avisa de cada pago a https://tu-dominio/api/billing/webhook." }))),
      h("div", { class: "card" },
        h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Planes" }),
          h("div", { class: "note", text: "Cada plan fija los límites de sus clientes. Los cambios se aplican al momento a quienes lo tienen." })),
          h("button", { class: "btn primary", onClick: () => planModal(null, reload) }, icon("plus"), "Nuevo plan")),
        data.plans.length ? h("div", { class: "blocked-list" }, data.plans.map((p) => h("div", { class: `blocked-row${p.active ? "" : " muted"}` },
          h("div", { class: "grow" },
            h("div", { class: "name" }, `${p.name} · ${p.price}${p.interval === "year" ? "/año" : "/mes"} `,
              p.active ? null : h("span", { class: "badge off", text: "Desactivado" }), p.public ? null : h("span", { class: "badge", text: "Privado" })),
            h("div", { class: "meta", text: `${planFeatures(p).slice(0, 5).join(" · ")} · ${p.tenants} clientes` })),
          h("button", { class: "btn ghost icon", title: "Editar", onClick: () => planModal(p, reload) }, icon("edit")),
          h("button", { class: "btn ghost icon", title: p.active ? "Desactivar (no se puede contratar)" : "Activar", onClick: () =>
            run(async () => { await api("PATCH", `/api/admin/plans/${p.id}`, { active: !p.active }); return api("GET", "/api/admin/billing"); }, p.active ? "Plan desactivado" : "Plan activado") }, icon("power")),
          p.tenants ? null : h("button", { class: "btn ghost icon", title: "Eliminar", onClick: async () => {
            if (await confirmDialog({ title: "Eliminar plan", message: `${p.name} se eliminará.`, confirmLabel: "Eliminar" })) {
              run(async () => { await api("DELETE", `/api/admin/plans/${p.id}`); return api("GET", "/api/admin/billing"); }, "Plan eliminado");
            }
          } }, icon("trash")))))
          : h("p", { class: "note", style: { margin: 0 }, text: "Crea tu primer plan, por ejemplo «Hogar» con 5 dispositivos por 4,99 €/mes." })),
      h("div", { class: "card" },
        h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Opciones" }))),
        h("div", { class: "grid", style: { gap: "16px" } },
          h("label", { class: "inline-field" }, "Si no paga, suspender tras",
            h("select", { class: "input", onChange: (e) => run(() => api("PUT", "/api/admin/billing/settings", { grace_days: Number(e.target.value) }), "Guardado") },
              [0, 3, 7, 14, 30].map((n) => h("option", { value: String(n), selected: n === data.settings.grace_days, text: n ? `${n} días` : "inmediatamente" }))),
            "de gracia"),
          h("div", { class: "field" }, h("label", { class: "switch" },
            h("input", { type: "checkbox", checked: data.settings.signup, onChange: (e) => run(() => api("PUT", "/api/admin/billing/settings", { signup: e.target.checked }), e.target.checked ? "Registro abierto" : "Registro cerrado") }),
            h("span", { class: "track" }), h("span", { text: "Registro público: cualquiera puede contratar un plan y su red se crea al pagar" })),
            data.settings.signup ? h("div", { class: "input-group", style: { marginTop: "8px", maxWidth: "520px" } }, input({ value: signupUrl, readonly: true, class: "input mono" }),
              h("button", { class: "btn icon", title: "Copiar", onClick: () => copyText(signupUrl, "Enlace copiado") }, icon("copy"))) : null),
          h("div", { class: "field" }, h("label", { class: "switch" },
            h("input", { type: "checkbox", checked: data.settings.tax, onChange: (e) => run(() => api("PUT", "/api/admin/billing/settings", { tax: e.target.checked }), "Guardado") }),
            h("span", { class: "track" }), h("span", { text: "Calcular el IVA automáticamente (Stripe Tax)" })),
            h("div", { class: "help", text: "Pide la dirección de facturación y añade el impuesto que corresponda. Actívalo antes en Stripe › Impuestos." })))));
  };
  fill(main, pageHead("Facturación", "Planes, suscripciones y cobros con Stripe"), body);
  draw();
}

/* ------------------------------------------------------------------ alta pública */
async function signupView(step) {
  if (step === "ok") {
    return publicShell(h("p", { class: "lead" }, h("b", { text: "¡Gracias!" }), " Estamos activando tu red privada (unos segundos)."),
      h("a", { class: "btn primary block", href: "#/" }, "Entrar"));
  }
  let info;
  try { info = await api("GET", "/api/signup"); } catch (e) { info = { enabled: false }; }
  if (!info.enabled) return publicShell(h("p", { class: "lead", text: "El registro no está abierto." }), h("a", { class: "btn block", href: "#/" }, "Volver"));
  const wanted = Number(hashParam("plan"));
  let chosen = info.plans.some((p) => p.id === wanted) ? wanted : (info.plans[0] ? info.plans[0].id : null);
  const err = h("div", { class: "help", style: { color: "var(--danger)", minHeight: "18px" } });
  const btn = h("button", { class: "btn primary block", type: "submit" }, "Continuar al pago");
  const cards = h("div", { class: "plan-pick" }, info.plans.map((p) => h("label", { class: "plan-option" },
    h("input", { type: "radio", name: "plan", value: String(p.id), checked: p.id === chosen, onChange: () => { chosen = p.id; } }),
    h("span", null, h("b", { text: p.name }), h("em", { text: `${p.price}${p.interval === "year" ? "/año" : "/mes"}` }),
      h("small", { text: planFeatures(p).slice(0, 4).join(" · ") })))));
  const form = h("form", { onSubmit: async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    err.textContent = "";
    btn.disabled = true;
    try {
      await openStripe("/api/signup", { name: fd.get("name"), email: fd.get("email"), username: fd.get("username"), password: fd.get("password"), plan_id: chosen });
    } catch (ex) { err.textContent = ex.message; btn.disabled = false; }
  } },
    cards,
    field("Nombre o empresa", input({ name: "name", required: true, maxlength: "64", autocomplete: "organization" })),
    field("Email", input({ name: "email", type: "email", required: true, autocomplete: "email" })),
    field("Usuario", input({ name: "username", required: true, pattern: "[A-Za-z0-9][A-Za-z0-9._\\-]{2,31}", autocomplete: "username", autocapitalize: "none", spellcheck: "false" })),
    field("Contraseña", input({ name: "password", type: "password", required: true, minlength: "8", autocomplete: "new-password" })),
    err, btn,
    h("p", { class: "note", style: { textAlign: "center", margin: 0 } }, "¿Ya tienes cuenta? ", h("a", { href: "#/", text: "Entrar" })));
  publicShell(h("p", { class: "lead", text: "Crea tu red privada" }), form);
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
      billingBanner(),
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
      defaultExitCard(me.id),
    );
  };
  await load();
  every(load);
}

function defaultExitCard(tenantId) {
  const card = h("div", { class: "card", hidden: true });
  exitOptions(tenantId).then((ex) => {
    if (!ex) return;
    const sel = h("select", { class: "input", onChange: async () => {
      try { await api("PUT", "/api/exits/default", { exit_id: Number(sel.value), ...(state.me.role === "admin" ? { tenant_id: tenantId } : {}) }); toast("Salida guardada"); }
      catch (e) { toast(e.message, "err"); }
    } }, [0, ...ex.exits.map((e) => e.id)].map((id) => h("option", { value: String(id), selected: id === ex.tenant_default, text: exitLabel(ex, id) })));
    fill(card, h("div", { class: "card-head" }, h("div", null, h("h2", { text: "Salida a Internet" }),
      h("div", { class: "note", text: "País desde el que navegan tus dispositivos con «todo el tráfico». Cada dispositivo puede elegir otro al editarlo." }))),
      h("div", { style: { maxWidth: "420px" } }, sel));
    card.hidden = false;
  });
  return card;
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

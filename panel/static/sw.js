/* Service worker del panel. __VERSION__ lo sustituye el servidor por un hash de
   los ficheros estáticos: cada despliegue nuevo instala un SW nuevo y limpia la
   caché anterior. La API nunca se cachea (datos en vivo y privados). */
"use strict";
const CACHE = "wgp-__VERSION__";
const SHELL = [
  "/",
  "/static/app.js",
  "/static/style.css",
  "/static/favicon.svg",
  "/manifest.webmanifest",
  "/static/icons/icon-192.png",
  "/static/icons/apple-touch-icon.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith("wgp-") && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  const url = new URL(req.url);
  if (req.method !== "GET" || url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/api/") || url.pathname === "/healthz") return; // siempre red

  if (req.mode === "navigate") {
    // Red primero; sin conexión, el shell cacheado (la app mostrará el error de API).
    event.respondWith(fetch(req).catch(() => caches.match("/")));
    return;
  }
  // Estáticos: caché primero y actualización en segundo plano.
  event.respondWith(
    caches.open(CACHE).then(async (cache) => {
      const cached = await cache.match(req);
      const network = fetch(req).then((res) => {
        if (res.ok) cache.put(req, res.clone());
        return res;
      }).catch(() => cached);
      return cached || network;
    }),
  );
});

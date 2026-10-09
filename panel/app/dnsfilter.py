"""Filtrado DNS por cliente: listas de uBlock Origin / AdGuard aplicadas a nivel DNS.

uBlock Origin es una extensión de navegador; dentro de una VPN lo equivalente es
resolver el DNS de los dispositivos en el servidor y aplicar ahí las mismas
listas (sólo las reglas de dominio, que son las que tienen sentido en DNS). Así
el filtrado funciona en cualquier dispositivo (móvil, TV, consola) sin instalar
nada.

Cada cliente activa las categorías que quiera; la política se elige por la IP de
origen (la red /24 del cliente) y cada dispositivo puede quedar exento.

Flujo de una consulta
---------------------
  1. Se localiza el cliente por la IP de origen (10.252.N.x -> cliente N).
  2. Lista blanca del cliente -> se resuelve normalmente.
  3. Lista negra del cliente o dominio en una categoría activa (y no exceptuado
     por la propia lista con @@) -> respuesta 0.0.0.0 / :: (bloqueado).
  4. Búsqueda segura -> CNAME a la versión restringida del buscador.
  5. Resto -> se reenvía a los servidores DNS de subida (con caché).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import socket
import sqlite3
import struct
import tempfile
import threading
import time
import urllib.request
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from pathlib import Path

from dnslib import AAAA, CNAME, QTYPE, RCODE, RR, A, DNSRecord

from .config import Settings
from .db import Database

log = logging.getLogger("wgp.dns")

# Linux: permite enlazar la IP del túnel aunque wg0 aún no exista.
IP_FREEBIND = getattr(socket, "IP_FREEBIND", 15)

BLOCK_TTL = 60
LIST_REFRESH_SECONDS = 24 * 3600
MAX_LIST_BYTES = 64 * 1024 * 1024


# ----------------------------------------------------------------------------- catálogo
@dataclass(frozen=True)
class Source:
    name: str
    urls: tuple[str, ...]  # el primero que responda; el resto son mirrors


@dataclass(frozen=True)
class Category:
    key: str
    name: str
    description: str
    sources: tuple[Source, ...]


CATEGORIES: tuple[Category, ...] = (
    Category(
        "ads", "Anuncios y rastreadores",
        "Bloquea publicidad, rastreadores y analítica con las listas de uBlock Origin y AdGuard.",
        (
            Source("AdGuard DNS filter", (
                "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
                "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/gh-pages/Filters/filter.txt",
            )),
            Source("Peter Lowe's Ad and tracking server list", (
                "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
            )),
        ),
    ),
    Category(
        "security", "Malware y phishing",
        "Bloquea dominios que distribuyen malware, estafas y suplantación de identidad.",
        (
            Source("URLhaus Malicious URL Blocklist", (
                "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
                "https://malware-filter.pages.dev/urlhaus-filter-hosts.txt",
            )),
            Source("Phishing URL Blocklist", (
                "https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt",
                "https://phishing-filter.pages.dev/phishing-filter-hosts.txt",
            )),
        ),
    ),
    Category(
        "adult", "Contenido para adultos",
        "Filtro familiar: bloquea pornografía y contenido sexual explícito.",
        (
            Source("StevenBlack porn", (
                "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
            )),
            Source("OISD NSFW small", ("https://nsfw-small.oisd.nl/",)),
        ),
    ),
    Category(
        "gambling", "Apuestas",
        "Bloquea casinos y casas de apuestas online.",
        (
            Source("StevenBlack gambling", (
                "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts",
            )),
        ),
    ),
)
CATEGORY_KEYS = tuple(c.key for c in CATEGORIES)
FILTER_KEYS = CATEGORY_KEYS + ("safesearch",)

# Búsqueda segura: el buscador se resuelve a su versión restringida (CNAME).
_GOOGLE = re.compile(r"^(www\.)?google\.(com|[a-z]{2}|com?\.[a-z]{2})$")
SAFESEARCH_EXACT = {
    "youtube.com": "restrictmoderate.youtube.com",
    "www.youtube.com": "restrictmoderate.youtube.com",
    "m.youtube.com": "restrictmoderate.youtube.com",
    "youtubei.googleapis.com": "restrictmoderate.youtube.com",
    "youtube.googleapis.com": "restrictmoderate.youtube.com",
    "www.youtube-nocookie.com": "restrictmoderate.youtube.com",
    "bing.com": "strict.bing.com",
    "www.bing.com": "strict.bing.com",
    "duckduckgo.com": "safe.duckduckgo.com",
    "www.duckduckgo.com": "safe.duckduckgo.com",
}

# Con filtros activos se desactiva el DNS-over-HTTPS automático de Firefox
# (si no, Firefox se saltaría el filtrado).
DOH_CANARY = "use-application-dns.net"


def safesearch_target(name: str) -> str | None:
    if _GOOGLE.match(name):
        return "forcesafesearch.google.com"
    return SAFESEARCH_EXACT.get(name)


# ----------------------------------------------------------------------------- listas
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+$")
_HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}
_COSMETIC = re.compile(r"\S#[@?$%]*#")  # «#» pegado a texto = cosmética; « #» = comentario
_IGNORED = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback", "0.0.0.0"}


def normalize_domain(value: str) -> str | None:
    """Valida y normaliza un dominio introducido por un usuario (o None)."""
    d = value.strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    if d.startswith("||") and d.endswith("^"):
        d = d[2:-1]
    return d if DOMAIN_RE.match(d) and d not in _IGNORED else None


def parse_list(text: str) -> tuple[set[str], set[str]]:
    """Extrae (bloqueados, excepciones) de una lista en formato hosts, ABP/uBlock o dominios.

    De la sintaxis ABP/uBlock sólo se usan las reglas de dominio completas
    (`||dominio^`, `@@||dominio^`), que son las aplicables en DNS; las reglas
    cosméticas, de URL o con modificadores se ignoran.
    """
    blocked: set[str] = set()
    allowed: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#![":
            continue
        allow = line.startswith("@@")
        if allow:
            line = line[2:]
        if _COSMETIC.search(line):
            continue  # reglas cosméticas (##, #@#, #?#, #$#...): no aplican a DNS
        if line.startswith("||"):
            body, _, mods = line[2:].partition("$")
            if mods and mods not in ("important", "all"):
                continue
            body = body.removesuffix("|")  # «^|»: ancla de fin, mismo significado en DNS
            if not body.endswith("^"):
                continue
            domain = body[:-1]
        elif allow:
            continue
        else:
            parts = line.split("#", 1)[0].split()
            if len(parts) >= 2 and parts[0] in _HOSTS_IPS:
                domain = parts[1]
            elif len(parts) == 1:
                domain = parts[0]
            else:
                continue
        domain = domain.lower().rstrip(".")
        if domain in _IGNORED or "*" in domain or not DOMAIN_RE.match(domain):
            continue
        (allowed if allow else blocked).add(domain)
    return blocked, allowed


def _suffixes(name: str):
    """a.b.example.com -> a.b.example.com, b.example.com, example.com, com"""
    parts = name.split(".")
    for i in range(len(parts)):
        yield ".".join(parts[i:])


def matches(name: str, domains) -> bool:
    return any(s in domains for s in _suffixes(name))


@dataclass
class CategoryData:
    blocked: frozenset[str] = frozenset()
    allowed: frozenset[str] = frozenset()
    updated: float | None = None


class ListStore:
    """Descarga, cachea en disco y carga en memoria las listas de cada categoría."""

    def __init__(self, directory: Path) -> None:
        self.dir = directory
        self.data: dict[str, CategoryData] = {c.key: CategoryData() for c in CATEGORIES}
        self._lock = threading.Lock()

    def _path(self, cat: Category, idx: int) -> Path:
        return self.dir / f"{cat.key}-{idx}.txt"

    def load_cached(self) -> None:
        for cat in CATEGORIES:
            self._load_category(cat)

    def _load_category(self, cat: Category) -> None:
        blocked: set[str] = set()
        allowed: set[str] = set()
        newest = None
        for idx, _source in enumerate(cat.sources):
            path = self._path(cat, idx)
            if not path.exists():
                continue
            b, a = parse_list(path.read_text(errors="replace"))
            blocked |= b
            allowed |= a
            newest = max(newest or 0, path.stat().st_mtime)
        with self._lock:
            self.data[cat.key] = CategoryData(frozenset(blocked), frozenset(allowed), newest)
        log.info("Categoría %s: %d dominios bloqueados, %d excepciones", cat.key, len(blocked), len(allowed))

    def stale(self) -> bool:
        return any(d.updated is None or time.time() - d.updated > LIST_REFRESH_SECONDS for d in self.data.values())

    def refresh(self) -> None:
        """Descarga todas las listas (bloqueante: ejecutar en un hilo)."""
        self.dir.mkdir(parents=True, exist_ok=True)
        for cat in CATEGORIES:
            changed = False
            for idx, source in enumerate(cat.sources):
                if self._download(source, self._path(cat, idx)):
                    changed = True
            if changed:
                self._load_category(cat)

    def _download(self, source: Source, dest: Path) -> bool:
        for url in source.urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "wgp-panel/1.0 (+dns filter)"})
                with urllib.request.urlopen(req, timeout=60) as res:
                    body = res.read(MAX_LIST_BYTES + 1)
                if len(body) > MAX_LIST_BYTES:
                    raise ValueError("lista demasiado grande")
                text = body.decode("utf-8", errors="replace")
                blocked, _ = parse_list(text)
                if not blocked:
                    raise ValueError("la lista no contiene dominios válidos")
                fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.")
                with open(fd, "w") as fh:
                    fh.write(text)
                Path(tmp).replace(dest)
                log.info("Lista %s actualizada desde %s (%d dominios)", source.name, url, len(blocked))
                return True
            except Exception as exc:  # noqa: BLE001 - se prueba el siguiente mirror
                log.warning("No se pudo descargar %s desde %s: %s", source.name, url, exc)
        return False

    def stats(self) -> dict[str, dict]:
        with self._lock:
            return {k: {"domains": len(v.blocked), "updated": v.updated} for k, v in self.data.items()}


# --------------------------------------------------------------------------- políticas
@dataclass(frozen=True)
class Policy:
    tenant_id: int
    categories: frozenset[str]
    safesearch: bool
    allow: frozenset[str]
    deny: frozenset[str]
    exempt: frozenset[str]  # IPs de dispositivos sin filtrado

    @property
    def active(self) -> bool:
        return bool(self.categories or self.safesearch or self.deny)


def parse_filters(raw: str | None) -> dict[str, bool]:
    try:
        data = json.loads(raw or "{}")
    except ValueError:
        data = {}
    return {k: bool(data.get(k, False)) for k in FILTER_KEYS}


def split_domains(raw: str | None) -> list[str]:
    return [d for d in (raw or "").split() if d]


def tenant_filtering_active(row: sqlite3.Row) -> bool:
    flags = parse_filters(row["dns_filters"])
    return any(flags.values()) or bool(split_domains(row["dns_deny"]))


@dataclass
class TenantStats:
    hours: dict[int, list[int]] = field(default_factory=dict)  # hora -> [consultas, bloqueadas]
    top: Counter = field(default_factory=Counter)
    recent: deque = field(default_factory=lambda: deque(maxlen=50))

    def record(self, blocked: bool, domain: str, client: str) -> None:
        hour = int(time.time() // 3600)
        bucket = self.hours.setdefault(hour, [0, 0])
        bucket[0] += 1
        if blocked:
            bucket[1] += 1
            self.top[domain] += 1
            if len(self.top) > 2000:
                self.top = Counter(dict(self.top.most_common(1000)))
            self.recent.appendleft((time.time(), domain, client))
        if len(self.hours) > 26:
            for h in sorted(self.hours)[:-25]:
                del self.hours[h]

    def summary(self) -> dict:
        now = int(time.time() // 3600)
        q = sum(v[0] for h, v in self.hours.items() if now - h < 24)
        b = sum(v[1] for h, v in self.hours.items() if now - h < 24)
        return {
            "queries_24h": q, "blocked_24h": b,
            "top": [{"domain": d, "count": n} for d, n in self.top.most_common(10)],
            "recent": [{"ts": int(ts), "domain": d, "client": c} for ts, d, c in list(self.recent)[:25]],
        }


# --------------------------------------------------------------------------- resolver
def _udp_limit(query: bytes) -> int:
    """Tamaño máximo de respuesta UDP que acepta el cliente (EDNS0 o 512)."""
    try:
        for rr in DNSRecord.parse(query).ar:
            if rr.rtype == QTYPE.OPT:
                return max(512, min(int(rr.rclass), 4096))
    except Exception:  # noqa: BLE001
        pass
    return 512


class _UdpServer(asyncio.DatagramProtocol):
    def __init__(self, owner: "DnsFilter") -> None:
        self.owner = owner
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        self.owner._spawn(self._answer(data, addr))

    async def _answer(self, data: bytes, addr) -> None:
        reply = await self.owner.handle(data, addr[0])
        if reply and self.transport:
            limit = _udp_limit(data)
            if len(reply) > limit:  # el cliente reintentará por TCP
                try:
                    rec = DNSRecord.parse(reply)
                    rec.rr, rec.auth, rec.ar = [], [], []
                    rec.header.tc = 1
                    reply = rec.pack()
                except Exception:  # noqa: BLE001
                    return
            self.transport.sendto(reply, addr)


class DnsFilter:
    def __init__(self, settings: Settings, database: Database) -> None:
        self.settings = settings
        self.db = database
        self.lists = ListStore(settings.data_dir / "lists")
        self.upstreams = settings.dns_upstreams
        self.upstream_port = 53
        self.bind = (str(settings.server_address.ip) if settings.dns_bind == "auto" else settings.dns_bind)
        self.port = settings.dns_port
        self.policies: dict[int, Policy] = {}
        self.stats: dict[int, TenantStats] = {}
        self.cache: OrderedDict[tuple, tuple[float, bytes]] = OrderedDict()
        self.running = False
        self.error: str | None = None
        self._servers: list = []
        self._tasks: set[asyncio.Task] = set()
        self._sem = asyncio.Semaphore(512)
        self._base = int(settings.wg_subnet.network_address)
        self._host_bits = 32 - settings.tenant_prefix

    # ------------------------------------------------------------------ políticas
    def reload_policies(self) -> None:
        with self.db.conn() as c:
            tenants = c.execute(
                "SELECT id, net_index, enabled, dns_filters, dns_allow, dns_deny FROM tenants"
            ).fetchall()
            exempt_rows = c.execute("SELECT tenant_id, ip FROM devices WHERE dns_filter = 0").fetchall()
        exempt: dict[int, set[str]] = {}
        for r in exempt_rows:
            exempt.setdefault(r["tenant_id"], set()).add(r["ip"])
        policies = {}
        for t in tenants:
            if not t["enabled"]:
                continue
            flags = parse_filters(t["dns_filters"])
            policies[t["net_index"]] = Policy(
                tenant_id=t["id"],
                categories=frozenset(k for k in CATEGORY_KEYS if flags[k]),
                safesearch=flags["safesearch"],
                allow=frozenset(split_domains(t["dns_allow"])),
                deny=frozenset(split_domains(t["dns_deny"])),
                exempt=frozenset(exempt.get(t["id"], ())),
            )
        self.policies = policies

    def policy_for(self, client_ip: str) -> Policy | None:
        try:
            ip = int(ipaddress.IPv4Address(client_ip))
        except ValueError:
            return None
        idx = (ip - self._base) >> self._host_bits
        return self.policies.get(idx) if idx > 0 else None

    def decide(self, name: str, policy: Policy | None, client_ip: str) -> tuple[str, str | None]:
        """('forward'|'block'|'nxdomain'|'safesearch', destino CNAME)."""
        if policy is None or client_ip in policy.exempt or not policy.active:
            return "forward", None
        if name == DOH_CANARY:
            return "nxdomain", None
        if policy.allow and matches(name, policy.allow):
            return "forward", None
        if policy.deny and matches(name, policy.deny):
            return "block", None
        data = self.lists.data
        for key in policy.categories:
            cat = data[key]
            if matches(name, cat.blocked) and not matches(name, cat.allowed):
                return "block", None
        if policy.safesearch:
            target = safesearch_target(name)
            if target:
                return "safesearch", target
        return "forward", None

    def tenant_stats(self, tenant_id: int) -> dict:
        st = self.stats.get(tenant_id)
        return st.summary() if st else TenantStats().summary()

    # ------------------------------------------------------------------ consultas
    async def handle(self, data: bytes, client_ip: str) -> bytes | None:
        try:
            req = DNSRecord.parse(data)
        except Exception:  # noqa: BLE001 - paquete malformado: se ignora
            return None
        if not req.questions:
            return None
        q = req.q
        name = str(q.qname).rstrip(".").lower()
        policy = self.policy_for(client_ip)
        action, target = self.decide(name, policy, client_ip)

        if policy is not None:
            st = self.stats.setdefault(policy.tenant_id, TenantStats())
            # El canario DoH es técnico: cuenta como consulta, no como bloqueo visible.
            st.record(action == "block", name, client_ip)

        if action == "forward":
            return await self.forward(data)
        reply = req.reply()
        if action == "nxdomain":
            reply.header.rcode = RCODE.NXDOMAIN
        elif action == "block":
            if q.qtype == QTYPE.A:
                reply.add_answer(RR(q.qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=BLOCK_TTL))
            elif q.qtype == QTYPE.AAAA:
                reply.add_answer(RR(q.qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=BLOCK_TTL))
        elif action == "safesearch":
            reply.add_answer(RR(q.qname, QTYPE.CNAME, rdata=CNAME(target), ttl=300))
            if q.qtype in (QTYPE.A, QTYPE.AAAA):
                upstream = await self.forward(DNSRecord.question(target, QTYPE[q.qtype]).pack())
                try:
                    for rr in DNSRecord.parse(upstream).rr:
                        reply.add_answer(rr)
                except Exception:  # noqa: BLE001
                    reply.header.rcode = RCODE.SERVFAIL
        return reply.pack()

    async def forward(self, data: bytes) -> bytes:
        try:
            req = DNSRecord.parse(data)
            key = (str(req.q.qname).lower(), req.q.qtype, req.q.qclass)
        except Exception:  # noqa: BLE001
            key = None
        if key is not None:
            hit = self.cache.get(key)
            if hit and hit[0] > time.monotonic():
                self.cache.move_to_end(key)
                return data[:2] + hit[1][2:]
        for server in self.upstreams:
            try:
                resp = await self._udp_query(server, data)
                if resp[2] & 0x02:  # TC: respuesta truncada -> TCP
                    resp = await self._tcp_query(server, data)
            except (OSError, asyncio.TimeoutError, IndexError):
                continue
            if key is not None:
                self._store(key, resp)
            return resp
        reply = DNSRecord.parse(data).reply()
        reply.header.rcode = RCODE.SERVFAIL
        return reply.pack()

    def _store(self, key: tuple, resp: bytes) -> None:
        try:
            rec = DNSRecord.parse(resp)
        except Exception:  # noqa: BLE001
            return
        if rec.header.rcode not in (RCODE.NOERROR, RCODE.NXDOMAIN):
            return
        ttls = [rr.ttl for rr in rec.rr] or [min((rr.ttl for rr in rec.auth), default=60)]
        ttl = max(0, min(min(ttls), 3600 if rec.rr else 300))
        if ttl == 0:
            return
        self.cache[key] = (time.monotonic() + ttl, resp)
        self.cache.move_to_end(key)
        while len(self.cache) > 20000:
            self.cache.popitem(last=False)

    async def _udp_query(self, server: str, data: bytes, timeout: float = 2.5) -> bytes:
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[bytes] = loop.create_future()

        class Client(asyncio.DatagramProtocol):
            def datagram_received(self, payload, addr):
                if not fut.done() and payload[:2] == data[:2]:
                    fut.set_result(payload)

            def error_received(self, exc):
                if not fut.done():
                    fut.set_exception(exc)

        transport, _ = await loop.create_datagram_endpoint(Client, remote_addr=(server, self.upstream_port))
        try:
            transport.sendto(data)
            return await asyncio.wait_for(fut, timeout)
        finally:
            transport.close()

    async def _tcp_query(self, server: str, data: bytes, timeout: float = 4.0) -> bytes:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(server, self.upstream_port), timeout)
        try:
            writer.write(struct.pack("!H", len(data)) + data)
            await writer.drain()
            (length,) = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), timeout))
            return await asyncio.wait_for(reader.readexactly(length), timeout)
        finally:
            writer.close()

    # ------------------------------------------------------------------ servidor
    def _spawn(self, coro) -> None:
        async def guarded():
            async with self._sem:
                await coro
        task = asyncio.ensure_future(guarded())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _socket(self, kind: int) -> socket.socket:
        sock = socket.socket(socket.AF_INET, kind)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_IP, IP_FREEBIND, 1)
        except OSError:
            pass
        sock.bind((self.bind, self.port))
        sock.setblocking(False)
        return sock

    async def _tcp_client(self, reader, writer) -> None:
        peer = writer.get_extra_info("peername") or ("", 0)
        try:
            while True:
                (length,) = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), 30))
                data = await asyncio.wait_for(reader.readexactly(length), 10)
                reply = await self.handle(data, peer[0])
                if not reply:
                    break
                writer.write(struct.pack("!H", len(reply)) + reply)
                await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, struct.error):
            pass
        finally:
            writer.close()

    async def start(self) -> None:
        self.reload_policies()
        await asyncio.to_thread(self.lists.load_cached)
        loop = asyncio.get_running_loop()
        try:
            udp = self._socket(socket.SOCK_DGRAM)
            if self.port == 0:  # puerto efímero (tests)
                self.port = udp.getsockname()[1]
            transport, _ = await loop.create_datagram_endpoint(lambda: _UdpServer(self), sock=udp)
            tcp = self._socket(socket.SOCK_STREAM)
            server = await asyncio.start_server(self._tcp_client, sock=tcp)
        except OSError as exc:
            self.error = f"No se pudo abrir {self.bind}:{self.port}: {exc}"
            log.error(self.error)
            return
        self._servers = [transport, server]
        self.running = True
        log.info("Resolver DNS con filtrado escuchando en %s:%d (subida: %s)",
                 self.bind, self.port, ", ".join(self.upstreams))
        self._spawn(self._refresh_loop())

    async def _refresh_loop(self) -> None:
        while True:
            if self.lists.stale():
                await asyncio.to_thread(self.lists.refresh)
            await asyncio.sleep(6 * 3600)

    async def stop(self) -> None:
        for s in self._servers:
            s.close()
        for t in list(self._tasks):
            t.cancel()
        self.running = False

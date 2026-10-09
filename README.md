# WireGuardVPS

Plataforma WireGuard **multi-tenant** con panel web propio: creas **clientes**, cada uno recibe su **red privada /24** y gestiona sus **propios dispositivos**. Los dispositivos de un mismo cliente se ven entre sí (LAN virtual); los de clientes distintos, nunca.

## Instalación (un solo comando)

En un VPS Debian 11+/Ubuntu 20.04+ limpio:

```bash
curl -fsSL https://raw.githubusercontent.com/matiormx/WireGuardVps/main/install.sh | sudo bash
```

`install.sh` instala lo mínimo (curl, certificados), descarga y valida `wg-manager.sh`, lo deja en `/usr/local/sbin/wg-manager` y ejecuta `wg-manager install`, que hace el resto: Docker, Compose, iptables, UFW, wireguard-tools, sysctl, build del panel, firewall multi-tenant y la interfaz `wg0`.

Al terminar, entra en `http://<IP-del-VPS>:5000` con `admin` / `admin`: el panel te obliga a cambiar la contraseña en el primer acceso.

Opciones por variables de entorno (solo en la primera instalación; después se guardan en `/etc/wg-manager.conf`):

```bash
curl -fsSL https://raw.githubusercontent.com/matiormx/WireGuardVps/main/install.sh \
  | sudo ADMIN_PASS='MiClaveTemporal' PUBLIC_ENDPOINT='vpn.midominio.com' bash
```

| Variable | Por defecto | Descripción |
|---|---|---|
| `ADMIN_USER` / `ADMIN_PASS` | `admin` / `admin` | Credenciales iniciales del administrador |
| `PUBLIC_ENDPOINT` | autodetectada | IP o dominio que usarán los dispositivos |
| `ENABLE_HTTPS` | `true` | Caddy con HTTPS automático para los dominios configurados en el panel |
| `PANEL_DOMAIN` | — | Dominio inicial del panel (opcional: también se configura desde *Ajustes*) |
| `ACME_EMAIL` | — | Email opcional para avisos de Let's Encrypt |
| `PANEL_PORT` | `5000` | Puerto del panel web (sin dominio) |
| `WG_PORT` | `51820` | Puerto UDP de WireGuard |
| `WG_SUBNET` | `10.252.0.0/16` | Bloque global (una /24 por cliente) |
| `WG_DNS` | `1.1.1.1, 1.0.0.1` | DNS de subida del resolver con filtros |
| `DNS_ENABLED` | `true` | Resolver propio con filtros por cliente (`false` = los dispositivos usan `WG_DNS` directamente) |
| `ENABLE_UFW` | `true` | Gestionar UFW (abre SSH, WireGuard y panel) |
| `WG_BRANCH` | `main` | Rama del repositorio a instalar |

Requisitos: systemd, kernel ≥ 5.6 (WireGuard integrado) y acceso root. En VPS LXC/OpenVZ el proveedor debe habilitar WireGuard y Docker.

## Inicio de sesión biométrico (passkeys)

Admin y clientes pueden entrar con **Face ID, Touch ID, la huella de Android o Windows Hello**:

- Tras entrar con la contraseña se sugiere activarlo en ese dispositivo. Si se pulsa «Ahora no», no se vuelve a sugerir en 30 días.
- En el login hay un botón **Entrar con llave biométrica**, sin escribir usuario ni contraseña.
- En **Cuenta → Inicio de sesión biométrico** se ven y se eliminan las llaves de cada dispositivo.

Usa el estándar WebAuthn: la biometría nunca sale del dispositivo y el servidor solo guarda una clave pública. Cada llave queda ligada al dominio en el que se creó, así que **requiere abrir el panel con su dominio y HTTPS** (*Ajustes → Dominio del panel*). Un cliente suspendido no puede entrar ni con su llave, y al eliminar un cliente se borran sus llaves.

## DNS propio de cada cliente

Cada cliente tiene su propio DNS en `10.252.0.1`, que los dispositivos usan automáticamente:

- **Nombres de los dispositivos:** se crean a partir de su nombre («Portátil de Ana» → `portatil-de-ana`) y se pueden cambiar desde la sección **DNS** del cliente o al editar el dispositivo.
- **Registros propios:** `nas → 10.252.1.50`, impresoras, servidores… (hasta 200 por cliente).
- **Sufijos de red:** los configura el admin en **Ajustes → DNS de la red** (por ejemplo `vpn, lan`, como en MikroTik). Van en la configuración WireGuard (`DNS = 10.252.0.1, vpn, lan`), así que `ping nas` se resuelve como `nas.vpn`. También funciona la resolución inversa (PTR).
- **Aislamiento:** un cliente solo resuelve los nombres de su propia red, y los sufijos internos nunca se consultan a Internet.
- **Reenvío propio (opcional):** cada cliente puede usar sus propios servidores DNS: públicos o uno de su red, nunca la red de otro cliente. Los filtros de navegación se siguen aplicando.

Los dispositivos creados antes de configurar los sufijos deben volver a importar su configuración (QR) para usar nombres cortos.

## Filtros de navegación (anuncios, malware y familia)

Cada cliente activa desde su panel (**Filtros**) lo que quiere bloquear en todos sus dispositivos:

| Filtro | Listas |
|---|---|
| Anuncios y rastreadores | AdGuard DNS filter, Peter Lowe's list (listas de uBlock Origin / AdGuard compatibles con DNS) |
| Malware y phishing | URLhaus Malicious URL Blocklist, Phishing URL Blocklist |
| Contenido para adultos | StevenBlack porn, OISD NSFW small |
| Apuestas | StevenBlack gambling |
| Búsqueda segura | SafeSearch obligatorio en Google, Bing y DuckDuckGo y modo restringido de YouTube |

Incluye perfiles rápidos (*Protección básica*, *Familia*, *Máxima*), listas propias de «siempre permitir» y «siempre bloquear», estadísticas de las últimas 24 h y un botón **Permitir** en cada dominio bloqueado. Cada dispositivo puede quedar **exento** (por ejemplo, el de un adulto).

**Cómo funciona:** uBlock Origin es una extensión de navegador; en una VPN lo equivalente es filtrar el DNS. El panel incluye un resolver en `10.252.0.1:53` que aplica a cada cliente sus filtros según la red de origen. Las listas se descargan y se actualizan cada 24 h, con mirrors de respaldo. Para que el filtro no se pueda saltar, en los clientes con filtros el host:

- redirige cualquier consulta DNS (puerto 53) al resolver, aunque el dispositivo tenga otro DNS configurado;
- bloquea DNS-over-TLS (853);
- desactiva el DNS-over-HTTPS automático de Firefox.

Los dispositivos en modo «solo red privada» creados antes de esta versión deben **reimportar su configuración** para usar el resolver. Los de «todo el tráfico» se filtran sin cambios.

## Dominios, HTTPS y app instalable (PWA)

Todo se configura **desde el panel**, sin entrar al servidor:

- **Admin → Ajustes → Dominio del panel:** escribe tu dominio (por ejemplo `vpn.tudominio.com`), crea un registro **A** hacia la IP del VPS y pulsa *Comprobar*. El certificado HTTPS de Let's Encrypt se emite solo y se renueva automáticamente. Cuando funcione, activa **Forzar HTTPS**: el acceso por `http://IP:5000` redirigirá al dominio.
- **Dominio propio de cada cliente:** cada cliente puede poner el suyo desde *Cuenta* (o el admin desde la ficha del cliente → *Dominio*), por ejemplo `vpn.suempresa.com`. En ese dominio el panel muestra su nombre (también como nombre de la app instalada) y solo puede entrar ese cliente.

Por dentro, Caddy funciona en modo *on-demand TLS*: la primera vez que se visita un dominio, pregunta al panel si está dado de alta y si su DNS apunta a este servidor; solo entonces pide el certificado. Así nadie puede generar certificados para dominios ajenos y no hay que reiniciar nada al añadir o quitar dominios. Se usan los puertos 80 y 443; para no instalar Caddy, usa `ENABLE_HTTPS=false`.

La app se instala desde el botón **Instalar app** (menú o pantalla de login):

- **iPhone/iPad:** Safari → Compartir → *Añadir a pantalla de inicio* (funciona también sin HTTPS).
- **Android/Chrome/Edge:** requieren HTTPS, es decir, un dominio configurado.

## Routers: redes completas (site-to-site)

Un cliente puede conectar **su oficina entera** con un router (MikroTik, OpenWrt, Linux…): al añadir un dispositivo elige **Router (red completa)** e indica la red de su LAN (p. ej. `192.168.88.0/24`). El panel genera:

- un **script para MikroTik (RouterOS 7)** listo para pegar en *Terminal*, y
- un `.conf` para Linux / OpenWrt.

Después, sus dispositivos móviles llegan a los equipos de la oficina y la oficina a ellos (impresoras, NAS, cámaras…). El tráfico de Internet de la oficina sigue saliendo por su propia conexión. Cada LAN debe ser única en la plataforma (si es `192.168.1.0/24`, mejor cambiarla por una menos común) y sigue aislada de los demás clientes.

## Servicios publicados con HTTPS

Cada cliente puede publicar en Internet un equipo de su red (NAS, cámaras, Home Assistant, un servidor web…) con **un nombre propio y HTTPS**: en **Servicios → Publicar servicio** indica el nombre (`nas.suempresa.com`), la IP del equipo (de su red o de la LAN de su router) y el puerto. Basta con crear un registro **A** de ese nombre hacia la IP del VPS: el certificado se emite solo. Opcionalmente, añade **usuario y contraseña** delante del servicio. El botón *Comprobar* verifica DNS, certificado y que el equipo responde. Requiere `ENABLE_HTTPS=true` (Caddy).

## Endpoint y copias de seguridad

- **Ajustes → Endpoint de WireGuard:** usa un nombre (p. ej. `wg.tudominio.com`, nube **gris** en Cloudflare) en lugar de la IP. Si un día cambias de servidor, basta con mover el DNS.
- **Ajustes → Copias de seguridad:** define una **frase de paso** (cifra las copias con AES-256; sin ella no se pueden restaurar) y activa la copia diaria. Se guardan en el servidor (con retención) y, opcionalmente, en cualquier almacenamiento **S3** (Amazon S3, Cloudflare R2, Backblaze B2, MinIO…). También puedes descargarlas desde el panel.
- **Restaurar en un servidor nuevo:**

  ```bash
  curl -fsSL https://raw.githubusercontent.com/matiormx/WireGuardVps/main/install.sh | sudo bash
  sudo wg-manager restore wgp-20261009-030000.wgpb
  ```

  Se recuperan clientes, dispositivos y sus claves, la clave del servidor, dominios, DNS, servicios y ajustes. Después apunta el DNS del endpoint (y de los dominios) al nuevo servidor: los dispositivos se reconectan solos.

## Cómo funciona

| | Admin | Cliente |
|---|---|---|
| Panel con estado del servidor, tráfico y clientes en línea | ✔ | |
| Crear, editar, suspender y eliminar clientes | ✔ | |
| Restablecer contraseñas de clientes | ✔ | |
| Crear, deshabilitar y borrar dispositivos | ✔ (de cualquier cliente) | ✔ (solo los suyos) |
| QR y descarga del `.conf` de cada dispositivo | ✔ | ✔ |
| Modo de túnel por dispositivo: todo el tráfico o solo la red privada | ✔ | ✔ |

**Direccionamiento:** el cliente *N* recibe `10.252.N.0/24` (hasta 255 clientes). Sus dispositivos usan `.2`–`.254` (hasta 253 por cliente, con un límite configurable). El servidor es `10.252.0.1`.

**Aislamiento:** todo el tráfico entre dispositivos entra y sale por `wg0`, y pasa por la cadena `WGP-TENANTS` del host:

```
FORWARD  -i wg0 -o wg0                  -> WGP-TENANTS
           -s 10.252.1.0/24 -d 10.252.1.0/24 -> ACCEPT   (LAN del cliente 1)
           -s 10.252.2.0/24 -d 10.252.2.0/24 -> ACCEPT   (LAN del cliente 2)
           ...                               -> DROP     (entre clientes)
FORWARD  -i wg0 -o <WAN> -s 10.252.0.0/16 -> ACCEPT   (salida a Internet)
FORWARD  -i <WAN> -o wg0  RELATED,ESTABLISHED -> ACCEPT
nat      -s 10.252.0.0/16 -o <WAN>          -> MASQUERADE
```

**Arquitectura:**

- `panel/`: FastAPI + SQLite + SPA sin dependencias externas. Corre en Docker (`network_mode: host`, `NET_ADMIN` solo para `wg syncconf` y `wg show`). Escribe `/etc/wireguard/wg0.conf` y aplica los cambios de peers en caliente, sin cortar sesiones.
- Host: `wg-quick@wg0` levanta la interfaz. Su `PostUp` llama a `wgp-firewall`, que crea las reglas base. Cuando el panel cambia los clientes, escribe `wgp/tenants.list`; una unidad systemd `.path` detecta el cambio y el host regenera `WGP-TENANTS`, validando cada línea. El contenedor nunca ejecuta iptables.
- Seguridad: contraseñas con scrypt; sesiones firmadas que se invalidan al cambiar la contraseña; cookie `HttpOnly` + `SameSite=Strict` y cabecera anti-CSRF; límite de intentos de login; CSP estricta.

## Comandos

| Comando | Descripción |
|---|---|
| `sudo wg-manager install` | Instalación completa (idempotente) |
| `sudo wg-manager update [--force] [--skip-self]` | Actualiza el script, el panel (`git pull` + build) y el firewall sin cortar conexiones |
| `sudo wg-manager status` | Panel, interfaz `wg0`, redes de cliente y reglas |
| `sudo wg-manager logs` | Logs del panel |
| `sudo wg-manager reset-admin` | Contraseña temporal para el admin si la pierdes |
| `sudo wg-manager backup` | Copia cifrada inmediata (en `/opt/wg-platform/data/backups`) |
| `sudo wg-manager restore <copia.wgpb>` | Restaura una copia (pide la frase de paso) |

## Desarrollo

```bash
cd panel
pip install -r requirements-dev.txt
python -m pytest -q                                   # API: aislamiento, permisos, CSRF, límites
DATA_DIR=/tmp/wgp WG_CONF_DIR=/tmp/wgp/wg python -m app.server   # http://localhost:5000
sudo tests/firewall_netns_test.sh                     # firewall con tráfico real (namespaces)
```

Para publicar una versión nueva del script, sube `readonly VERSION="x.y.z"` en `wg-manager.sh`; `wg-manager update` solo lo sustituye si la versión remota es mayor.

> ⚠️ Hasta que configures un dominio y actives *Forzar HTTPS* (en *Ajustes*), el panel también responde por HTTP en el puerto 5000.

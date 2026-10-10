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

La app se instala desde el botón **Instalar app** (menú o pantalla de login). Siempre se instala desde el **dominio del panel** que configuraste: si entras por la IP, por la página pública u otro nombre, el botón te lleva a ese dominio y allí la instalas (los dominios propios de clientes instalan su propia app con su nombre):

- **iPhone/iPad:** Safari → Compartir → *Añadir a pantalla de inicio* (funciona también sin HTTPS).
- **Android/Chrome/Edge:** requieren HTTPS, es decir, un dominio configurado.

## Routers: redes completas (site-to-site)

Un cliente puede conectar **su oficina entera** con un router (MikroTik, OpenWrt, Linux…): al añadir un dispositivo elige **Router (red completa)** e indica la red de su LAN (p. ej. `192.168.88.0/24`). El panel genera:

- un **script para MikroTik (RouterOS 7)** listo para pegar en *Terminal*, y
- un `.conf` para Linux / OpenWrt.

Después, sus dispositivos móviles llegan a los equipos de la oficina y la oficina a ellos (impresoras, NAS, cámaras…). El tráfico de Internet de la oficina sigue saliendo por su propia conexión. Cada LAN debe ser única en la plataforma (si es `192.168.1.0/24`, mejor cambiarla por una menos común) y sigue aislada de los demás clientes.

## Servicios publicados con HTTPS

Cada cliente puede publicar en Internet un equipo de su red (NAS, cámaras, Home Assistant, un servidor web…) con **un nombre propio y HTTPS**: en **Servicios → Publicar servicio** indica el nombre (`nas.suempresa.com`), la IP del equipo (de su red o de la LAN de su router) y el puerto. Basta con crear un registro **A** de ese nombre hacia la IP del VPS: el certificado se emite solo. Opcionalmente, añade **usuario y contraseña** delante del servicio. El botón *Comprobar* verifica DNS, certificado y que el equipo responde. Requiere `ENABLE_HTTPS=true` (Caddy).

## Subdominio de cada cliente (Cloudflare)

Si tu dominio está en Cloudflare, en **Ajustes › Subdominios de clientes** pega un token de la API (Cloudflare › Mi perfil › Tokens de API › Crear token › plantilla «Editar DNS de zona», limitado a tu dominio), elige el dominio y activa «Un subdominio por cliente». El panel crea y mantiene solo:

- `usuario.tudominio.com` → IP del servidor: los puertos abiertos se usan como `acme.tudominio.com:3389`.
- `*.usuario.tudominio.com` → IP del servidor (opcional): sus servicios HTTPS funcionan al momento con nombres como `nas.acme.tudominio.com`, sin tocar el DNS.

Son registros «solo DNS» (nube gris), porque los puertos TCP/UDP no pasan por el proxy de Cloudflare. El panel sólo modifica los registros que crea él; si ya existe otro con ese nombre, no lo toca y te lo indica. El subdominio sale del nombre de usuario y se puede cambiar desde la ficha del cliente; al borrar un cliente se borra su registro, y «Desconectar» elimina todos los del panel. Dentro de tu dominio, cada cliente sólo puede usar nombres de su propio subdominio.

## Puertos abiertos (TCP/UDP)

Para lo que no es web (escritorio remoto, cámaras RTSP, SSH, juegos…), cada cliente puede abrir puertos en **Puertos → Abrir puerto**: `IP_del_VPS:3389 → 10.252.1.20:3389` (TCP, UDP o ambos), hacia un dispositivo o un equipo de la LAN de su router. El equipo ve la conexión como si viniera del servidor de la VPN, así la respuesta vuelve siempre por el túnel. El admin fija cuántos puede abrir cada cliente (5 por defecto, 0 = ninguno); los clientes usan puertos ≥ 1024 y nunca los del propio servidor (SSH, panel, WireGuard, 53, 80, 443). Las reglas las crea el host (`wgp-firewall`), que valida cada línea.

## Usuarios de cada cliente

En **Usuarios**, el responsable de un cliente invita a sus empleados o familiares con un enlace (de un solo uso, 7 días) o les crea la cuenta. Cada usuario entra con su propia cuenta (también con llave biométrica) y sólo ve **sus** dispositivos, su actividad y sus avisos; el responsable lo ve todo y decide si pueden añadir dispositivos por su cuenta.

Para instalar un dispositivo sin dar una cuenta, usa el botón **Enlace de instalación** de su fila: una página temporal (1 h, 24 h o 7 días) con el QR, el archivo y las instrucciones, para mandarla por WhatsApp o email. Se puede anular en cualquier momento.

## Actividad y avisos

- **Actividad:** tráfico por hora, día y mes (24 h, 7 días, 30 días y 12 meses), dispositivos y clientes que más consumen, consultas y bloqueos del filtro DNS con los dominios más bloqueados, y un registro de conexiones con la IP pública de origen. También por dispositivo (botón de actividad en su fila). Se guarda el detalle por hora 8 días y por día 2 años.
- **Avisos:** si un dispositivo **vigilado** (los routers, por defecto) deja de conectar unos minutos, llega un aviso, y otro cuando vuelve. Cada persona elige dónde recibirlos: **notificaciones** en el móvil u ordenador (en iPhone, desde la app instalada), **Telegram** o **email**. Los administradores también reciben los fallos de las copias de seguridad.
- Para Telegram y email, el admin los configura una vez en **Ajustes → Avisos**: un bot creado con [@BotFather](https://t.me/BotFather) (se pega su token) y un servidor SMTP. Cada persona vincula su Telegram con un clic desde **Avisos**.


**Email de los avisos:** en Ajustes › Avisos › Email eliges **SMTP** (Gmail, Brevo, tu hosting…) o **Cloudflare** (Cloudflare Email Service): da de alta tu dominio en Cloudflare › Email Service, crea un token con el permiso «Email Sending: Edit» (puede ser el mismo de los subdominios si le añades ese permiso) y escribe el remitente, p. ej. `Avisos <avisos@tudominio.com>`; la cuenta se deduce sola del dominio. «Probar» envía un email de prueba.
## Salidas por país

Tus clientes pueden navegar con la IP de otro país sin cambiar nada en sus dispositivos: siguen conectados a este servidor (red privada, DNS y filtros incluidos) y sólo su tráfico de Internet sale por la salida elegida. Hay dos tipos:

**IP adicional (lo más sencillo).** Una IP extra de este mismo VPS geolocalizada en otro país, por ejemplo las IPs adicionales de OVH (Bare Metal Cloud › IP › Contratar IP adicional, eliges el país y la asignas a tu VPS). En **Ajustes → Salidas por país → Añadir salida → IP adicional** pones su nombre, país e IP: el panel la configura en el servidor y los dispositivos que la elijan salen con ella. Sin otro servidor y sin latencia extra. Las webs ven el país según las bases de datos de geolocalización; los servicios que miden latencia (algunas plataformas de vídeo) pueden notar que el servidor no está allí.

**Servidor en otro país.** Presencia real en el país (latencia local):

1. **Ajustes → Salidas por país → Añadir salida → Servidor en otro país**: nombre, país e IP del VPS de ese país.
2. En ese VPS (Debian/Ubuntu, el más pequeño vale) ejecuta el comando que muestra el panel:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/matiormx/WireGuardVps/main/install.sh | sudo bash -s -- exit-node <token>
   ```

   Si tu proveedor tiene firewall propio, abre el puerto UDP indicado (51821 por defecto).
3. En menos de un minuto aparece **Conectada**. Cada cliente elige su salida por defecto en *Mi red* y cada dispositivo puede cambiarla al editarlo (sólo con «Enviar todo el tráfico por la VPN»).

Si una salida deja de responder, sus dispositivos vuelven a salir por el servidor principal y recibes un aviso (puedes desactivar ese respaldo en una salida concreta si prefieres que se queden sin Internet antes que salir por otro país).

## Planes y cobros (Stripe)

En **Facturación**:

1. **Conecta Stripe** pegando tu clave secreta (`sk_live_…`, o `sk_test_…` para probar). El panel crea solo el webhook y los productos. Necesita el dominio del panel con HTTPS.
2. **Crea planes** (precio en €, mensual o anual, días de prueba) con sus límites: dispositivos, usuarios, puertos abiertos, servicios HTTPS y salidas por país. Cambiar un plan aplica los límites al momento a todos sus clientes.
3. Cada cliente ve su plan, su uso y sus facturas en **Plan**, contrata o cambia de plan (con prorrateo) y gestiona su tarjeta en el portal de Stripe.
4. **Impagos:** periodo de gracia configurable (7 días por defecto) y después suspensión automática; al pagar se reactiva solo. El cliente suspendido sólo puede entrar a pagar. Tus suspensiones manuales nunca se levantan solas.
5. **Registro público** (opcional): cualquiera elige un plan en `https://tu-dominio/#/signup`, paga y su red se crea al momento.
6. Clientes que te pagan por otros medios: en su ficha, **Plan → Plan manual o gratuito** (límites del plan, sin cobro ni suspensión automática).
7. **Clientes gratuitos** para tus proyectos: marca «Cliente gratuito» al crearlo (o en **Plan → Plan manual o gratuito**). Nunca se les cobra ni se suspenden, no ven planes que contratar y no cuentan en los ingresos. Si tenía una suscripción, se cancela en Stripe.

Opcional: IVA automático con Stripe Tax. Recibes avisos de nuevas suscripciones, cancelaciones y cobros fallidos, y el cliente de sus problemas de pago.

## Marca: nombre y logo

En **Ajustes › Marca** cambias el nombre de la aplicación (y el nombre corto que aparece bajo el icono en el móvil) y subes tu logo (PNG, JPG, WebP o SVG; mejor cuadrado y con fondo transparente). El panel genera los iconos de la app instalada (iPhone y Android, con el color de fondo que elijas), el de la pestaña del navegador y el del menú, con vista previa antes de guardar. Se usan también en la página pública, los avisos y los emails. «Restaurar original» vuelve al escudo por defecto. El logo se guarda en la base de datos, así que va incluido en las copias de seguridad.

## Página pública

Una web de presentación de tu servicio, con tus planes y botones para entrar o crear cuenta, en un dominio propio distinto del de la VPN (p. ej. `midominio.com` mientras el panel está en `vpn.midominio.com`). En **Ajustes › Página pública**: escribe el dominio (o varios, como `midominio.com, www.midominio.com`), crea sus registros **A** hacia la IP del VPS y activa «Publicar la página». Se sirve en el puerto 443 con certificado automático. Los textos (nombre, titular, descripción, email de contacto y aviso legal) se editan desde ahí; los planes salen de **Facturación**.

En ese dominio, el panel queda en `/dashboard` (puedes cambiarla en **Ajustes › Página pública › Dirección del panel**, p. ej. `/mi-cuenta`; los enlaces antiguos a `/app` redirigen): «Entrar» lleva al login y «Contratar» al registro con el plan elegido (si el registro público está activo; si no, a tu email). Tras pagar, el cliente vuelve al mismo dominio.

## Endpoint y copias de seguridad

- **Ajustes → Endpoint de WireGuard:** usa un nombre (p. ej. `wg.tudominio.com`, nube **gris** en Cloudflare) en lugar de la IP. Si un día cambias de servidor, basta con mover el DNS.
- **Ajustes → Copias de seguridad:** define una **frase de paso** (cifra las copias con AES-256; sin ella no se pueden restaurar) y activa la copia diaria. Se guardan en el servidor (con retención) y, opcionalmente, en cualquier almacenamiento **S3** (Amazon S3, Cloudflare R2, Backblaze B2, MinIO…). También puedes descargarlas desde el panel.
- **Restaurar en un servidor nuevo:** instala la plataforma, entra al panel nuevo y pulsa **Restaura una copia de seguridad** (en el Panel) o **Ajustes › Copias de seguridad › Restaurar una copia**: elige el archivo `.wgpb`, escribe su frase de paso, revisa el resumen y confirma. Después entra con el usuario y la contraseña del servidor anterior. También por consola:

  ```bash
  curl -fsSL https://raw.githubusercontent.com/matiormx/WireGuardVps/main/install.sh | sudo bash
  sudo wg-manager restore wgp-20261009-030000.wgpb
  ```

  (por consola, si la red de la copia es distinta, se ajusta también la configuración del servidor).

  Se recuperan clientes, dispositivos y sus claves, la clave del servidor, dominios, DNS, servicios y ajustes. Después apunta el DNS del endpoint (y de los dominios) al nuevo servidor: los dispositivos se reconectan solos.

## Monitor del servidor

En **Servidor** (menú del administrador) ves el uso del VPS en tiempo real: CPU, memoria, disco, red (interfaz pública), carga y tiempo encendido, con gráficos de la última hora, 24 h, 7 días y 30 días (media y máximo). El Panel muestra un resumen de CPU, memoria y disco. Se mide cada 10 segundos y el historial ocupa muy poco (un punto por minuto durante 48 h y uno por hora durante 400 días).

Avisos a los administradores (Avisos › «Servidor»): disco al 90 % o más, memoria por encima del 90 % durante 10 minutos o CPU por encima del 90 % durante 15 minutos, y otro aviso cuando vuelve a la normalidad.

## Actualizaciones

En **Ajustes › Actualizaciones** ves la versión instalada y la publicada, y puedes pulsar **Actualizar** para que el servidor ejecute `wg-manager update` por su cuenta (panel, firewall y script). El panel se reinicia unos segundos; los túneles VPN no se cortan. Al terminar se recarga solo y queda el registro de la actualización.

Activa **Actualizar automáticamente** y elige el día (todos o uno de la semana) y la hora: a esa hora, si hay una versión nueva, se instala. Los administradores reciben un aviso con el resultado (Telegram, email o push, como los fallos de copia).

Las instalaciones anteriores a la 2.11.0 necesitan actualizar una vez por consola (`sudo wg-manager update`) para instalar el actualizador; desde entonces, todo desde el panel.

## Cómo funciona

| | Admin | Cliente |
|---|---|---|
| Panel con estado del servidor, tráfico y clientes en línea | ✔ | |
| Crear, editar, suspender y eliminar clientes | ✔ | |
| Restablecer contraseñas de clientes | ✔ | |
| Crear, deshabilitar y borrar dispositivos | ✔ (de cualquier cliente) | ✔ (solo los suyos) |
| Usuarios propios con invitación; enlaces de instalación | ✔ | ✔ |
| Actividad (tráfico, DNS, conexiones) y avisos | ✔ (toda la plataforma) | ✔ (su red) |
| Servicios HTTPS y puertos abiertos | ✔ | ✔ (con límite) |
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
| `sudo wg-manager exit-node <token>` | Convierte un VPS en salida por país (el token lo da el panel) |

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

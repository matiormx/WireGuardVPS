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
| `PANEL_PORT` | `5000` | Puerto del panel web |
| `WG_PORT` | `51820` | Puerto UDP de WireGuard |
| `WG_SUBNET` | `10.252.0.0/16` | Bloque global (una /24 por cliente) |
| `WG_DNS` | `1.1.1.1, 1.0.0.1` | DNS para dispositivos en modo «todo el tráfico» |
| `ENABLE_UFW` | `true` | Gestionar UFW (abre SSH, WireGuard y panel) |
| `WG_BRANCH` | `main` | Rama del repositorio a instalar |

Requisitos: systemd, kernel ≥ 5.6 (WireGuard integrado) y acceso root. En VPS LXC/OpenVZ el proveedor debe habilitar WireGuard y Docker.

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

## Desarrollo

```bash
cd panel
pip install -r requirements-dev.txt
python -m pytest -q                                   # API: aislamiento, permisos, CSRF, límites
DATA_DIR=/tmp/wgp WG_CONF_DIR=/tmp/wgp/wg python -m app.server   # http://localhost:5000
sudo tests/firewall_netns_test.sh                     # firewall con tráfico real (namespaces)
```

Para publicar una versión nueva del script, sube `readonly VERSION="x.y.z"` en `wg-manager.sh`; `wg-manager update` solo lo sustituye si la versión remota es mayor.

> ⚠️ El panel se sirve por HTTP. Ponle delante un proxy con TLS (Caddy, Nginx) o limita el acceso: `ufw delete allow 5000/tcp && ufw allow from <tu-IP> to any port 5000`.

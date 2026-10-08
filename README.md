# WireGuardVPS

Plataforma WireGuard **multi-tenant** basada en [wireguard-ui](https://github.com/ngoduykhanh/wireguard-ui) + Docker, desplegada y mantenida por `wg-manager.sh`.

## Instalación

```bash
curl -fsSL https://raw.githubusercontent.com/matiormx/wireguardvps/main/wg-manager.sh -o wg-manager.sh
chmod +x wg-manager.sh
sudo ./wg-manager.sh install
```

Requisitos: Debian 11+/Ubuntu 20.04+, systemd, kernel ≥ 5.6 y acceso root.

## Comandos

| Comando | Descripción |
|---|---|
| `sudo wg-manager install` | Instalación completa (idempotente) |
| `sudo wg-manager update [--force] [--skip-self]` | Auto-actualiza el script desde GitHub y la imagen Docker |
| `sudo wg-manager status` | Contenedores, interfaz `wg0` y reglas iptables |
| `wg-manager help` | Ayuda |

## Arquitectura

- `wireguard-ui` corre en Docker (`network_mode: host`) y **sólo escribe** `/etc/wireguard/wg0.conf`.
- La interfaz `wg0` la gestiona el host con `wg-quick@wg0`; una unidad `wg-platform-reload.path` detecta cada *Apply Config* del panel y aplica los cambios en caliente (`wg syncconf`).
- Hooks `PreUp/PostUp/PreDown/PostDown` inyectados en la BD de wireguard-ui:
  - `DROP` de `wg0 → wg0` dentro de `10.252.0.0/16` (los clientes no se ven entre sí).
  - `ACCEPT` de salida a Internet y retorno *stateful*.
  - `MASQUERADE` por la interfaz WAN.
- Configuración local persistente en `/etc/wg-manager.conf` (no se sobrescribe al actualizar).

## Publicar una nueva versión

Incrementa `readonly VERSION="x.y.z"` en `wg-manager.sh` y súbelo a la rama `main`. `wg-manager update` sólo sustituye el script si la versión remota es mayor.

> ⚠️ Cambia las credenciales por defecto (`admin`/`admin`) tras el primer acceso y protege el puerto 5000 (proxy TLS o `ufw allow from <IP> to any port 5000`).

#!/usr/bin/env bash
# =============================================================================
#  install.sh — Instalador "one-liner" de la plataforma WireGuard Multi-Tenant
# -----------------------------------------------------------------------------
#  Uso (en un VPS Debian/Ubuntu limpio, como root):
#
#    curl -fsSL https://raw.githubusercontent.com/matiormx/WireGuardVps/main/install.sh | sudo bash
#
#  Con opciones (se reenvían a wg-manager):
#
#    curl -fsSL .../install.sh | sudo bash -s -- install
#    curl -fsSL .../install.sh | sudo bash -s -- update --force
#
#  Variables de entorno opcionales (se heredan en wg-manager.sh):
#    WG_REPO_RAW      Base RAW del repositorio (por defecto, este repo)
#    WG_BRANCH        Rama a descargar (por defecto: main)
#    ADMIN_PASS       Contraseña inicial del admin (por defecto: admin; se
#                     obliga a cambiarla en el primer acceso)
#    PUBLIC_ENDPOINT  IP/dominio público si la autodetección no sirve
#    ENABLE_UFW       true/false
#    ...y cualquier otra variable de la cabecera de wg-manager.sh
#
#  Qué hace:
#    1. Comprueba root, SO (apt + systemd) y arquitectura.
#    2. Instala lo mínimo para arrancar (curl, ca-certificates).
#    3. Descarga wg-manager.sh, valida su integridad y lo instala en
#       /usr/local/sbin/wg-manager.
#    4. Ejecuta "wg-manager install", que instala el resto de dependencias
#       (Docker, Compose, iptables, ufw, jq, git, wireguard-tools...), descarga
#       y construye el panel y despliega la plataforma completa.
# =============================================================================

set -euo pipefail

# Todo el código va dentro de main() y se invoca en la última línea: si la
# descarga vía "curl | bash" se corta a medias, bash no ejecuta nada parcial.
main() {
    local raw_base="${WG_REPO_RAW:-https://raw.githubusercontent.com/matiormx/WireGuardVps}"
    local branch="${WG_BRANCH:-main}"
    local target="/usr/local/sbin/wg-manager"
    local url="${raw_base%/}/${branch}/wg-manager.sh"

    local c_r="" c_g="" c_y="" c_b="" c_0=""
    if [[ -t 1 ]]; then
        c_r=$'\033[1;31m' c_g=$'\033[1;32m' c_y=$'\033[1;33m' c_b=$'\033[1;34m' c_0=$'\033[0m'
    fi
    info() { printf '%s[INFO]%s  %s\n' "${c_b}" "${c_0}" "$*"; }
    ok()   { printf '%s[ OK ]%s  %s\n' "${c_g}" "${c_0}" "$*"; }
    warn() { printf '%s[WARN]%s  %s\n' "${c_y}" "${c_0}" "$*" >&2; }
    die()  { printf '%s[ERROR]%s %s\n' "${c_r}" "${c_0}" "$*" >&2; exit 1; }

    # --- 1. Comprobaciones previas -------------------------------------------
    [[ "${EUID}" -eq 0 ]] || die "Ejecute como root: curl -fsSL <url>/install.sh | sudo bash"
    [[ -r /etc/os-release ]] || die "SO no soportado (falta /etc/os-release)."
    grep -Eqi '^(ID|ID_LIKE)=.*(debian|ubuntu)' /etc/os-release \
        || die "SO no soportado: se requiere Debian 11+ o Ubuntu 20.04+."
    command -v apt-get >/dev/null 2>&1 || die "apt-get no disponible."
    command -v systemctl >/dev/null 2>&1 || die "systemd es obligatorio."
    case "$(uname -m)" in
        x86_64|aarch64|armv7l) ;;
        *) warn "Arquitectura $(uname -m) no probada; se continúa." ;;
    esac
    if [[ -f /proc/1/environ ]] && grep -qa 'container=lxc\|container=openvz' /proc/1/environ 2>/dev/null; then
        warn "Contenedor LXC/OpenVZ detectado: WireGuard y Docker pueden no funcionar sin soporte del host."
    fi

    # --- 2. Dependencias mínimas de arranque ---------------------------------
    export DEBIAN_FRONTEND=noninteractive
    if ! command -v curl >/dev/null 2>&1 || [[ ! -s /etc/ssl/certs/ca-certificates.crt ]]; then
        info "Instalando curl y ca-certificates..."
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends curl ca-certificates >/dev/null
    fi
    ok "Dependencias de arranque listas."

    # --- 3. Descarga y validación de wg-manager.sh ---------------------------
    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf -- "${tmp}"' EXIT

    info "Descargando ${url}"
    curl -fsSL --retry 3 --max-time 60 -H 'Cache-Control: no-cache' -o "${tmp}/wg-manager.sh" "${url}" \
        || die "No se pudo descargar wg-manager.sh (¿repositorio público y rama '${branch}' correcta?)."
    head -n1 "${tmp}/wg-manager.sh" | grep -Eq '^#!.*bash' || die "El fichero descargado no es un script bash."
    bash -n "${tmp}/wg-manager.sh" || die "wg-manager.sh tiene errores de sintaxis."
    install -m 0755 "${tmp}/wg-manager.sh" "${target}"
    ok "wg-manager instalado en ${target} ($("${target}" version))."

    # --- 4. Despliegue completo ----------------------------------------------
    # Se exportan REPO_URL/BRANCH para que las auto-actualizaciones usen la
    # misma rama. stdin se redirige a /dev/null: con "curl | bash" stdin es
    # la tubería del propio script y no debe heredarse.
    rm -rf -- "${tmp}"; trap - EXIT   # exec no dispara el trap EXIT
    export BRANCH="${branch}"
    [[ $# -gt 0 ]] || set -- install
    info "Ejecutando: wg-manager $*"
    exec "${target}" "$@" </dev/null
}

main "$@"

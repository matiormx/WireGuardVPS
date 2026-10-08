#!/usr/bin/env bash
# =============================================================================
#  wg-manager.sh — Plataforma WireGuard Multi-Tenant (wireguard-ui + Docker)
# -----------------------------------------------------------------------------
#  Despliega y mantiene:
#    * Docker + Docker Compose (plugin v2)
#    * Tuning del kernel (ip_forward + buffers UDP)
#    * wireguard-ui (ngoduykhanh/wireguard-ui) en network_mode: host
#    * Interfaz WireGuard del host (wg-quick@wg0) gestionada por systemd y
#      recargada automáticamente cuando wireguard-ui reescribe wg0.conf
#    * Aislamiento multi-tenant: los peers NO pueden verse entre sí, sólo
#      salen a Internet a través de NAT (MASQUERADE)
#    * Auto-actualización del propio script desde GitHub (RAW) y de la imagen
#
#  Uso:
#    sudo ./wg-manager.sh install           Instalación completa
#    sudo ./wg-manager.sh update [--force]  Auto-actualización + contenedores
#    sudo ./wg-manager.sh status            Estado de la plataforma
#    ./wg-manager.sh help                   Ayuda
#
#  Sistemas soportados: Debian 11+/Ubuntu 20.04+ (gestor apt, systemd,
#  kernel >= 5.6 con módulo WireGuard integrado).
# =============================================================================

set -o errexit   # set -e : aborta ante cualquier comando que falle
set -o nounset   # set -u : aborta ante variables no definidas
set -o pipefail  # un pipeline falla si falla cualquiera de sus etapas
set -o errtrace  # set -E : el trap ERR se hereda en funciones y subshells

# -----------------------------------------------------------------------------
# VERSIÓN DEL SCRIPT (se compara con la versión publicada en GitHub)
# Incrementar siguiendo SemVer en cada publicación.
# -----------------------------------------------------------------------------
readonly VERSION="1.0.1"

# =============================================================================
#  CONFIGURACIÓN EDITABLE
# -----------------------------------------------------------------------------
#  Todos los valores pueden sobrescribirse de forma persistente en
#  /etc/wg-manager.conf (se genera en la instalación). Ese fichero NO se toca
#  durante las auto-actualizaciones, de modo que la configuración local
#  sobrevive a la sustitución del script.
# =============================================================================
readonly CONFIG_FILE="/etc/wg-manager.conf"
if [[ -f "${CONFIG_FILE}" ]]; then
    # shellcheck source=/dev/null
    source "${CONFIG_FILE}"
fi

# --- Repositorio de auto-actualización ---------------------------------------
: "${REPO_URL:=https://github.com/matiormx/WireGuardVps}"
: "${BRANCH:=main}"
: "${SCRIPT_REMOTE_PATH:=wg-manager.sh}"       # ruta del script dentro del repo

# --- Rutas de la plataforma ---------------------------------------------------
: "${PLATFORM_DIR:=/opt/wg-platform}"
: "${INSTALL_BIN:=/usr/local/sbin/wg-manager}"  # copia instalada del script
: "${LOG_FILE:=/var/log/wg-manager.log}"

# --- wireguard-ui ---------------------------------------------------------------
: "${WG_UI_IMAGE:=ngoduykhanh/wireguard-ui:latest}"
: "${WG_UI_CONTAINER:=wireguard-ui}"
: "${WGUI_BIND:=0.0.0.0}"                       # IP de escucha del panel web
: "${WGUI_PORT:=5000}"                          # puerto del panel web
: "${WGUI_ADMIN_USER:=admin}"                   # ¡CAMBIAR tras el primer login!
: "${WGUI_ADMIN_PASS:=admin}"                   # ¡CAMBIAR tras el primer login!

# --- WireGuard -------------------------------------------------------------------
: "${WG_INTERFACE:=wg0}"
: "${WG_SUBNET:=10.252.0.0/16}"                 # subred de todos los tenants
: "${WG_SERVER_ADDRESS:=10.252.0.1/16}"         # IP del servidor dentro del túnel
: "${WG_PORT:=51820}"                           # puerto UDP de WireGuard
: "${WG_DNS:=1.1.1.1,1.0.0.1}"                  # DNS que se entrega a los clientes
: "${WG_MTU:=1420}"
: "${WG_KEEPALIVE:=25}"
: "${WG_CLIENT_ALLOWED_IPS:=0.0.0.0/0}"         # full-tunnel por defecto

# --- Red del host ------------------------------------------------------------------
: "${PUBLIC_ENDPOINT:=}"                        # vacío = autodetección de IP pública
: "${WAN_IFACE:=}"                              # vacío = interfaz de la ruta por defecto
: "${ENABLE_UFW:=true}"                         # gestionar UFW (INPUT) automáticamente

# --- Kernel ------------------------------------------------------------------------
readonly SYSCTL_FILE="/etc/sysctl.d/99-wireguard.conf"
readonly NET_BUFFER_SIZE="2500000"

# --- Derivadas (no editar) ---------------------------------------------------------
readonly WG_CONF_DIR="/etc/wireguard"
readonly WG_CONF_FILE="${WG_CONF_DIR}/${WG_INTERFACE}.conf"
readonly COMPOSE_FILE="${PLATFORM_DIR}/docker-compose.yml"
readonly ENV_FILE="${PLATFORM_DIR}/.env"
readonly DB_DIR="${PLATFORM_DIR}/db"
readonly DB_SERVER_IFACE="${DB_DIR}/server/interfaces.json"
readonly LOCK_FILE="/var/lock/wg-manager.lock"
readonly RULE_TAG="wg-manager"                  # comentario iptables para identificar reglas
readonly RELOAD_HELPER="/usr/local/sbin/wg-platform-reload"
readonly SYSTEMD_DIR="/etc/systemd/system"

# Ruta absoluta del script en ejecución (vacía si se ejecuta vía "curl | bash").
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || true)"
[[ -f "${SCRIPT_PATH}" ]] || SCRIPT_PATH=""
readonly ORIGINAL_ARGS=("$@")

# Comando docker compose detectado en tiempo de ejecución (plugin v2 o v1).
DOCKER_COMPOSE=()
# Directorios temporales a limpiar en la salida.
TMP_PATHS=()
# Variables globales con los hooks de wg-quick (se calculan en build_hooks).
HOOK_PRE_UP="" HOOK_POST_UP="" HOOK_PRE_DOWN="" HOOK_POST_DOWN=""

# =============================================================================
#  SALIDA CON COLORES Y LOGGING
# =============================================================================
if [[ -t 1 ]]; then
    readonly C_RESET=$'\033[0m'  C_BOLD=$'\033[1m'
    readonly C_RED=$'\033[1;31m' C_GREEN=$'\033[1;32m'
    readonly C_YELLOW=$'\033[1;33m' C_BLUE=$'\033[1;34m' C_CYAN=$'\033[1;36m'
else
    readonly C_RESET="" C_BOLD="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_CYAN=""
fi

_log_file() {
    # Escribe en el log sin colores. Nunca debe abortar el script.
    { printf '%s [%s] %s\n' "$(date '+%F %T')" "$1" "$2" >>"${LOG_FILE}"; } 2>/dev/null || true
}
info()    { printf '%s[INFO]%s  %s\n' "${C_BLUE}" "${C_RESET}" "$*"; _log_file INFO "$*"; }
warn()    { printf '%s[WARN]%s  %s\n' "${C_YELLOW}" "${C_RESET}" "$*" >&2; _log_file WARN "$*"; }
error()   { printf '%s[ERROR]%s %s\n' "${C_RED}" "${C_RESET}" "$*" >&2; _log_file ERROR "$*"; }
success() { printf '%s[ OK ]%s  %s\n' "${C_GREEN}" "${C_RESET}" "$*"; _log_file OK "$*"; }
step()    { printf '\n%s==> %s%s\n' "${C_CYAN}${C_BOLD}" "$*" "${C_RESET}"; _log_file STEP "$*"; }
die()     { error "$*"; exit 1; }

# =============================================================================
#  TRAPS: errores y limpieza
# =============================================================================
on_error() {
    local exit_code=$1 line=$2 cmd=$3
    error "Fallo en la línea ${line} (código ${exit_code}): ${cmd}"
    error "Revise el log: ${LOG_FILE}"
}
cleanup() {
    local p
    for p in "${TMP_PATHS[@]+"${TMP_PATHS[@]}"}"; do
        [[ -n "${p}" && -e "${p}" ]] && rm -rf -- "${p}"
    done
    return 0
}
trap 'on_error $? ${LINENO} "${BASH_COMMAND}"' ERR
trap cleanup EXIT

# =============================================================================
#  UTILIDADES
# =============================================================================
check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "Este script requiere privilegios de superusuario. Ejecute: sudo $0 ${ORIGINAL_ARGS[*]-}"
    fi
}

os_release_field() {
    sed -n -E "s/^$1=[\"']?([^\"']*)[\"']?\$/\1/p" /etc/os-release | head -n1
}

check_os() {
    # Sólo se soporta la familia Debian (apt) con systemd. /etc/os-release se
    # parsea (no se hace "source") porque define su propia variable VERSION,
    # que colisionaría con la VERSION readonly de este script.
    [[ -r /etc/os-release ]] || die "No se encuentra /etc/os-release; SO no soportado."
    local os_id os_like os_name
    os_id="$(os_release_field ID)"
    os_like="$(os_release_field ID_LIKE)"
    os_name="$(os_release_field PRETTY_NAME)"
    case "${os_id}:${os_like}" in
        debian:*|ubuntu:*|*:*debian*|*:*ubuntu*) ;;
        *) die "Distribución no soportada (${os_name}). Se requiere Debian/Ubuntu." ;;
    esac
    command -v apt-get >/dev/null 2>&1 || die "apt-get no disponible."
    command -v systemctl >/dev/null 2>&1 || die "systemd es obligatorio."
    info "Sistema detectado: ${os_name} (kernel $(uname -r))"
}

acquire_lock() {
    # Evita ejecuciones concurrentes (p. ej. un cron de update + un install manual).
    mkdir -p "$(dirname "${LOCK_FILE}")"
    exec 9>"${LOCK_FILE}"
    if ! flock -n 9; then
        die "Ya hay otra instancia de wg-manager en ejecución (${LOCK_FILE})."
    fi
}

release_lock() {
    # flock se asocia a la descripción de fichero: cerrar fd 9 libera el lock.
    exec 9>&- || true
}

make_tmp_dir() {
    local d
    d="$(mktemp -d /tmp/wg-manager.XXXXXX)"
    TMP_PATHS+=("${d}")
    printf '%s' "${d}"
}

is_ipv4() {
    local ip=$1 o
    [[ "${ip}" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do (( 10#${o} <= 255 )) || return 1; done
    return 0
}

# version_gt A B  -> verdadero si A > B (comparación SemVer con sort -V)
version_gt() {
    [[ "$1" != "$2" ]] && [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" == "$1" ]]
}

detect_compose() {
    if docker compose version >/dev/null 2>&1; then
        DOCKER_COMPOSE=(docker compose)
    elif command -v docker-compose >/dev/null 2>&1; then
        DOCKER_COMPOSE=(docker-compose)
    else
        return 1
    fi
}

compose() {
    "${DOCKER_COMPOSE[@]}" --project-directory "${PLATFORM_DIR}" -f "${COMPOSE_FILE}" "$@"
}

detect_wan_iface() {
    # La interfaz WAN es la que tiene la ruta por defecto IPv4. Es la interfaz
    # sobre la que se aplica el MASQUERADE (SNAT dinámico) del tráfico de los
    # clientes hacia Internet.
    if [[ -z "${WAN_IFACE}" ]]; then
        WAN_IFACE="$(ip -4 route show default 2>/dev/null \
            | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit }}')"
    fi
    [[ -n "${WAN_IFACE}" ]] || die "No se pudo detectar la interfaz WAN. Defina WAN_IFACE en ${CONFIG_FILE}."
    ip link show "${WAN_IFACE}" >/dev/null 2>&1 || die "La interfaz WAN '${WAN_IFACE}' no existe."
}

detect_public_ip() {
    # Devuelve la IP pública IPv4 consultando varios servicios; si todos
    # fallan, recurre a la IP primaria de la interfaz WAN (útil en VPS sin NAT).
    local svc ip=""
    if [[ -n "${PUBLIC_ENDPOINT}" ]]; then
        printf '%s' "${PUBLIC_ENDPOINT}"; return 0
    fi
    for svc in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com https://ipv4.icanhazip.com; do
        ip="$(curl -4 -fsS --max-time 6 "${svc}" 2>/dev/null | tr -d '[:space:]' || true)"
        if is_ipv4 "${ip}"; then printf '%s' "${ip}"; return 0; fi
    done
    ip="$(ip -4 -o addr show dev "${WAN_IFACE}" scope global 2>/dev/null \
        | awk '{split($4, a, "/"); print a[1]; exit}')"
    if is_ipv4 "${ip}"; then printf '%s' "${ip}"; return 0; fi
    return 1
}

detect_ssh_ports() {
    # Detecta los puertos reales de sshd para no bloquear la sesión al activar UFW.
    local ports=""
    if command -v sshd >/dev/null 2>&1; then
        ports="$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }' | sort -u | tr '\n' ' ' || true)"
    fi
    if [[ -z "${ports// /}" ]]; then
        ports="$(ss -H -tlnp 2>/dev/null | awk '/"sshd"/ { n = split($4, a, ":"); print a[n] }' \
            | sort -u | tr '\n' ' ' || true)"
    fi
    [[ -n "${ports// /}" ]] || ports="22"
    printf '%s' "${ports}"
}

random_secret() {
    openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

# =============================================================================
#  FASE 1 — PREPARACIÓN DEL SISTEMA OPERATIVO
# =============================================================================
prepare_os() {
    step "Fase 1/7: Preparación del sistema operativo"
    export DEBIAN_FRONTEND=noninteractive
    info "Actualizando índices de paquetes..."
    apt-get update -qq
    info "Instalando dependencias base..."
    # wireguard-tools aporta wg/wg-quick en el HOST: la interfaz wg0 vive en el
    # host y la gestiona systemd; wireguard-ui sólo escribe la configuración.
    apt-get install -y -qq --no-install-recommends \
        ca-certificates curl wget gnupg lsb-release \
        iptables ufw git jq openssl iproute2 \
        wireguard-tools >/dev/null
    success "Dependencias instaladas."
}

# =============================================================================
#  FASE 2 — INSTALACIÓN DE DOCKER
# =============================================================================
install_docker() {
    step "Fase 2/7: Docker Engine y Docker Compose"
    if command -v docker >/dev/null 2>&1; then
        info "Docker ya instalado: $(docker --version)"
    else
        info "Instalando Docker con el script oficial (get.docker.com)..."
        local tmp
        tmp="$(make_tmp_dir)"
        curl -fsSL --retry 3 https://get.docker.com -o "${tmp}/get-docker.sh"
        sh "${tmp}/get-docker.sh" >/dev/null
        success "Docker instalado: $(docker --version)"
    fi

    systemctl enable --now docker >/dev/null 2>&1 || die "No se pudo iniciar el servicio docker."

    if ! detect_compose; then
        info "Instalando plugin docker-compose-plugin..."
        apt-get install -y -qq docker-compose-plugin >/dev/null \
            || die "No se pudo instalar Docker Compose."
        detect_compose || die "Docker Compose sigue sin estar disponible."
    fi
    success "Docker Compose disponible: $("${DOCKER_COMPOSE[@]}" version --short 2>/dev/null || echo ok)"
}

# =============================================================================
#  FASE 3 — TUNING DEL KERNEL
# =============================================================================
setup_sysctl() {
    step "Fase 3/7: Tuning del kernel (sysctl)"
    cat >"${SYSCTL_FILE}" <<EOF
# Generado por wg-manager ${VERSION} — $(date -u '+%F %T UTC')
#
# ip_forward=1: convierte el host en router. Sin esto, los paquetes que entran
# por wg0 con destino a Internet se descartan en lugar de reenviarse por la
# interfaz WAN (la cadena FORWARD de netfilter nunca llegaría a evaluarse).
net.ipv4.ip_forward = 1

# Buffers máximos de socket (recepción/envío). WireGuard trabaja sobre UDP y
# con muchos peers concurrentes los buffers por defecto (~208 KB) provocan
# descartes en ráfagas; 2.5 MB absorbe picos sin coste relevante de memoria.
net.core.rmem_max = ${NET_BUFFER_SIZE}
net.core.wmem_max = ${NET_BUFFER_SIZE}
EOF
    sysctl -p "${SYSCTL_FILE}" >/dev/null
    # UFW puede reaplicar su propio sysctl al arrancar; garantizamos coherencia.
    if [[ -f /etc/ufw/sysctl.conf ]]; then
        sed -i -E 's|^#?[[:space:]]*net/ipv4/ip_forward[[:space:]]*=.*|net/ipv4/ip_forward=1|' /etc/ufw/sysctl.conf
    fi
    [[ "$(sysctl -n net.ipv4.ip_forward)" == "1" ]] || die "ip_forward no quedó activo."
    success "Parámetros de kernel aplicados (${SYSCTL_FILE})."

    # Verificación del módulo WireGuard (integrado desde el kernel 5.6).
    if ! modprobe wireguard 2>/dev/null; then
        if ! ip link add wgtest0 type wireguard 2>/dev/null; then
            die "El kernel no soporta WireGuard (requiere >= 5.6 o el módulo wireguard-dkms)."
        fi
        ip link del wgtest0 2>/dev/null || true
    fi
    success "Soporte WireGuard en kernel verificado."
}

# =============================================================================
#  FASE 4 — FIREWALL DE ENTRADA (UFW)
# =============================================================================
setup_firewall() {
    step "Fase 4/7: Firewall de entrada (UFW)"
    if [[ "${ENABLE_UFW}" != "true" ]]; then
        warn "ENABLE_UFW=false: UFW no se gestiona. Abra manualmente ${WG_PORT}/udp y ${WGUI_PORT}/tcp."
        return 0
    fi
    # UFW controla sólo la cadena INPUT (servicios del propio host). El
    # reenvío de los túneles se gestiona con reglas propias insertadas en la
    # cabeza de FORWARD por los hooks de wg-quick (ver build_hooks), por lo
    # que la política DEFAULT_FORWARD_POLICY="DROP" de UFW se mantiene como
    # red de seguridad para cualquier otro tráfico reenviado.
    local p
    for p in $(detect_ssh_ports); do
        ufw allow "${p}/tcp" comment 'SSH' >/dev/null
        info "Permitido SSH en ${p}/tcp (anti-bloqueo)."
    done
    ufw allow "${WG_PORT}/udp" comment 'WireGuard' >/dev/null
    ufw allow "${WGUI_PORT}/tcp" comment 'wireguard-ui' >/dev/null
    ufw --force enable >/dev/null
    success "UFW activo: SSH, ${WG_PORT}/udp y ${WGUI_PORT}/tcp permitidos."
}

# =============================================================================
#  HOOKS DE wg-quick — AISLAMIENTO MULTI-TENANT + NAT
# -----------------------------------------------------------------------------
#  wg-quick ejecuta (eval) cada hook al levantar/bajar la interfaz y sustituye
#  %i por el nombre de la interfaz. Las reglas se insertan con posición
#  explícita en la CABEZA de la cadena FORWARD para que se evalúen antes que
#  las cadenas de Docker (DOCKER-USER/DOCKER-FORWARD) y de UFW (ufw-*):
#
#   FORWARD #1  -i wg0 -o wg0 -s SUBNET -d SUBNET          -> DROP
#               Tráfico transversal cliente->cliente. En WireGuard, un paquete
#               de un peer hacia otro peer entra por wg0 y sale por wg0 tras la
#               decisión de enrutamiento; al descartarlo aquí, cada tenant sólo
#               ve al servidor (10.252.0.1, cadena INPUT) e Internet.
#   FORWARD #2  -i wg0 -o WAN -s SUBNET                    -> ACCEPT
#               Salida de los clientes hacia Internet.
#   FORWARD #3  -i WAN -o wg0 -d SUBNET ctstate REL,EST    -> ACCEPT
#               Sólo retorno de conexiones iniciadas por el cliente (stateful):
#               desde Internet no se pueden abrir conexiones hacia los peers.
#   nat/POSTROUTING  -s SUBNET -o WAN                      -> MASQUERADE
#               SNAT dinámico a la IP de la WAN; conntrack deshace la
#               traducción en las respuestas.
#
#  Todas las reglas llevan "-m comment --comment wg-manager" para poder
#  auditarlas (iptables -S | grep wg-manager). Se evita usar los caracteres
#  < > & ' " en los hooks porque wireguard-ui renderiza wg0.conf mediante
#  plantillas Go y podría escaparlos.
#
#  Orden de ciclo de vida:
#   PreUp    : limpia restos de una ejecución anterior (idempotencia tras un
#              crash o un kill -9 de wg-quick).
#   PostUp   : inserta las 4 reglas.
#   PreDown  : retira primero NAT y ACCEPT (corta la salida a Internet).
#   PostDown : retira el DROP en último lugar, con la interfaz ya destruida,
#              de modo que el aislamiento nunca queda abierto ni un instante.
# =============================================================================
build_hooks() {
    detect_wan_iface
    local ipt="iptables -w"
    local tag="-m comment --comment ${RULE_TAG}"
    local r_iso="-i %i -o %i -s ${WG_SUBNET} -d ${WG_SUBNET} ${tag} -j DROP"
    local r_out="-i %i -o ${WAN_IFACE} -s ${WG_SUBNET} ${tag} -j ACCEPT"
    local r_ret="-i ${WAN_IFACE} -o %i -d ${WG_SUBNET} -m conntrack --ctstate RELATED,ESTABLISHED ${tag} -j ACCEPT"
    local r_nat="-s ${WG_SUBNET} -o ${WAN_IFACE} ${tag} -j MASQUERADE"

    local del_iso="${ipt} -D FORWARD ${r_iso} || true"
    local del_out="${ipt} -D FORWARD ${r_out} || true"
    local del_ret="${ipt} -D FORWARD ${r_ret} || true"
    local del_nat="${ipt} -t nat -D POSTROUTING ${r_nat} || true"

    HOOK_PRE_UP="${del_iso}; ${del_out}; ${del_ret}; ${del_nat}"
    HOOK_POST_UP="${ipt} -I FORWARD 1 ${r_iso}; ${ipt} -I FORWARD 2 ${r_out}; ${ipt} -I FORWARD 3 ${r_ret}; ${ipt} -t nat -I POSTROUTING 1 ${r_nat}"
    HOOK_PRE_DOWN="${del_nat}; ${del_ret}; ${del_out}"
    HOOK_POST_DOWN="${del_iso}"
}

# =============================================================================
#  FASE 5 — GENERACIÓN Y DESPLIEGUE DEL STACK DOCKER
# =============================================================================
deploy_stack() {
    step "Fase 5/7: Despliegue de wireguard-ui en ${PLATFORM_DIR}"
    build_hooks

    local endpoint
    endpoint="$(detect_public_ip)" || die "No se pudo determinar la IP pública. Defina PUBLIC_ENDPOINT en ${CONFIG_FILE}."
    info "Endpoint público de WireGuard: ${endpoint}:${WG_PORT}"
    info "Interfaz WAN para NAT: ${WAN_IFACE}"

    install -d -m 0750 "${PLATFORM_DIR}" "${DB_DIR}"
    install -d -m 0700 "${WG_CONF_DIR}"

    # El SESSION_SECRET firma las cookies de sesión del panel; se conserva entre
    # reinstalaciones para no invalidar sesiones ni romper el login.
    local session_secret=""
    if [[ -f "${ENV_FILE}" ]]; then
        session_secret="$(sed -n -E "s/^SESSION_SECRET='?([^']*)'?$/\1/p" "${ENV_FILE}" | head -n1)"
    fi
    [[ -n "${session_secret}" ]] || session_secret="$(random_secret)"

    # Fichero .env con permisos 600 (contiene credenciales y secretos).
    # NOTA: WGUI_ENDPOINT_ADDRESS es la dirección PÚBLICA que se escribe como
    # "Endpoint" en la configuración de los clientes; la subred del túnel
    # (10.252.0.0/16) se define en WGUI_SERVER_INTERFACE_ADDRESSES.
    # Las variables WGUI_SERVER_* sólo se aplican cuando wireguard-ui crea su
    # base de datos por primera vez; después manda la BD (db/server/*.json),
    # que este script sincroniza en configure_isolation().
    umask 077
    cat >"${ENV_FILE}" <<EOF
# Generado por wg-manager ${VERSION} — $(date -u '+%F %T UTC')
WGUI_USERNAME='${WGUI_ADMIN_USER}'
WGUI_PASSWORD='${WGUI_ADMIN_PASS}'
SESSION_SECRET='${session_secret}'
BIND_ADDRESS='${WGUI_BIND}:${WGUI_PORT}'
WGUI_ENDPOINT_ADDRESS='${endpoint}'
WGUI_SERVER_INTERFACE_ADDRESSES='${WG_SERVER_ADDRESS}'
WGUI_SERVER_LISTEN_PORT='${WG_PORT}'
WGUI_DNS='${WG_DNS}'
WGUI_MTU='${WG_MTU}'
WGUI_PERSISTENT_KEEPALIVE='${WG_KEEPALIVE}'
WGUI_DEFAULT_CLIENT_ALLOWED_IPS='${WG_CLIENT_ALLOWED_IPS}'
WGUI_DEFAULT_CLIENT_ENABLE_AFTER_CREATION='true'
WGUI_CONFIG_FILE_PATH='${WG_CONF_FILE}'
WGUI_SERVER_POST_UP_SCRIPT='${HOOK_POST_UP}'
WGUI_SERVER_POST_DOWN_SCRIPT='${HOOK_POST_DOWN}'
WGUI_MANAGE_START='false'
WGUI_MANAGE_RESTART='false'
WGUI_LOG_LEVEL='INFO'
EOF
    umask 022
    chmod 600 "${ENV_FILE}"

    # network_mode: host -> el panel escucha directamente en el host y no hay
    # NAT de Docker de por medio. wireguard-ui no necesita NET_ADMIN porque NO
    # levanta la interfaz: sólo escribe /etc/wireguard/wg0.conf, y systemd en el
    # host (wg-quick@wg0 + unidad .path) aplica los cambios.
    cat >"${COMPOSE_FILE}" <<EOF
# Generado por wg-manager ${VERSION} — $(date -u '+%F %T UTC')
services:
  wireguard-ui:
    image: ${WG_UI_IMAGE}
    container_name: ${WG_UI_CONTAINER}
    restart: unless-stopped
    network_mode: host
    env_file:
      - .env
    volumes:
      - ./db:/app/db
      - ${WG_CONF_DIR}:${WG_CONF_DIR}
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
EOF

    info "Validando docker-compose.yml..."
    compose config -q
    info "Descargando imagen ${WG_UI_IMAGE}..."
    compose pull -q
    compose up -d --remove-orphans
    wait_for_ui || die "wireguard-ui no responde en el puerto ${WGUI_PORT}. Ver: docker logs ${WG_UI_CONTAINER}"
    success "wireguard-ui en ejecución."
}

wait_for_ui() {
    local _
    for _ in $(seq 1 60); do
        if curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:${WGUI_PORT}/login" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# =============================================================================
#  FASE 6 — INYECCIÓN DEL AISLAMIENTO MULTI-TENANT
# =============================================================================
configure_isolation() {
    step "Fase 6/7: Inyección de reglas PreUp/PostUp/PreDown/PostDown"
    build_hooks

    # 1) Esperar a que wireguard-ui inicialice su base de datos JSON.
    local _
    for _ in $(seq 1 60); do
        [[ -s "${DB_SERVER_IFACE}" ]] && break
        sleep 1
    done
    [[ -s "${DB_SERVER_IFACE}" ]] || die "No apareció ${DB_SERVER_IFACE}; wireguard-ui no inicializó la BD."

    # 2) Escribir los hooks en la BD (fuente de verdad del panel). Así cada vez
    #    que un administrador pulse "Apply Config", wireguard-ui regenerará
    #    wg0.conf con las reglas de aislamiento incluidas.
    local tmp_json
    tmp_json="$(make_tmp_dir)/interfaces.json"
    jq --arg pre_up "${HOOK_PRE_UP}" --arg post_up "${HOOK_POST_UP}" \
       --arg pre_down "${HOOK_PRE_DOWN}" --arg post_down "${HOOK_POST_DOWN}" \
       '.pre_up = $pre_up | .post_up = $post_up | .pre_down = $pre_down
        | .post_down = $post_down | .updated_at = (now | todate)' \
       "${DB_SERVER_IFACE}" >"${tmp_json}"
    jq -e . "${tmp_json}" >/dev/null || die "JSON resultante inválido; no se modifica la BD."
    cp -p "${DB_SERVER_IFACE}" "${DB_SERVER_IFACE}.bak"
    cat "${tmp_json}" >"${DB_SERVER_IFACE}"   # conserva inode/permisos del bind mount
    success "Hooks inyectados en la BD de wireguard-ui."

    # 3) Reiniciar el contenedor para que recargue la BD sin caché.
    compose restart "wireguard-ui" >/dev/null
    wait_for_ui || die "wireguard-ui no volvió a responder tras el reinicio."

    # 4) Regenerar wg0.conf: primero vía API oficial ("Apply Config"); si falla
    #    (p. ej. contraseña ya cambiada), se parchea wg0.conf de forma directa.
    if apply_config_via_api; then
        success "wg0.conf regenerado vía API de wireguard-ui."
    else
        warn "No se pudo usar la API (¿credenciales cambiadas?). Se parchea ${WG_CONF_FILE} directamente."
        patch_wg_conf
    fi

    grep -q -- "--comment ${RULE_TAG}" "${WG_CONF_FILE}" 2>/dev/null \
        || die "Las reglas no están presentes en ${WG_CONF_FILE}."
    success "Aislamiento multi-tenant configurado en ${WG_CONF_FILE}."
}

apply_config_via_api() {
    local jar base="http://127.0.0.1:${WGUI_PORT}" user pass resp
    jar="$(make_tmp_dir)/cookies"
    user="$(sed -n -E "s/^WGUI_USERNAME='?([^']*)'?$/\1/p" "${ENV_FILE}" | head -n1)"
    pass="$(sed -n -E "s/^WGUI_PASSWORD='?([^']*)'?$/\1/p" "${ENV_FILE}" | head -n1)"

    resp="$(curl -fsS --max-time 10 -c "${jar}" -H 'Content-Type: application/json' \
        -H "Origin: ${base}" -X POST "${base}/login" \
        -d "$(jq -cn --arg u "${user}" --arg p "${pass}" '{username: $u, password: $p, rememberMe: false}')" \
        2>/dev/null)" || return 1
    jq -e '.success == true' >/dev/null 2>&1 <<<"${resp}" || return 1

    resp="$(curl -fsS --max-time 15 -b "${jar}" -H 'Content-Type: application/json' \
        -H "Origin: ${base}" -X POST "${base}/api/apply-wg-config" 2>/dev/null)" || return 1
    jq -e '.success == true' >/dev/null 2>&1 <<<"${resp}" || return 1
    [[ -s "${WG_CONF_FILE}" ]]
}

patch_wg_conf() {
    # Reescribe sólo la sección [Interface]: elimina cualquier Pre/PostUp/Down
    # previo e inserta los nuevos hooks justo tras la cabecera. Los [Peer] no
    # se tocan. wireguard-ui generará lo mismo desde la BD en el próximo
    # "Apply Config", por lo que no hay deriva entre panel y fichero.
    [[ -s "${WG_CONF_FILE}" ]] || die "${WG_CONF_FILE} no existe todavía. Entre en el panel y pulse 'Apply Config', luego ejecute: $0 update"
    local tmp
    tmp="$(make_tmp_dir)/wg.conf"
    awk -v pre_up="${HOOK_PRE_UP}" -v post_up="${HOOK_POST_UP}" \
        -v pre_down="${HOOK_PRE_DOWN}" -v post_down="${HOOK_POST_DOWN}" '
        BEGIN { in_iface = 0 }
        /^[[:space:]]*\[Interface\][[:space:]]*$/ {
            print; in_iface = 1
            print "PreUp = " pre_up
            print "PostUp = " post_up
            print "PreDown = " pre_down
            print "PostDown = " post_down
            next
        }
        /^[[:space:]]*\[/ { in_iface = 0 }
        in_iface && /^[[:space:]]*(PreUp|PostUp|PreDown|PostDown)[[:space:]]*=/ { next }
        { print }
    ' "${WG_CONF_FILE}" >"${tmp}"
    cp -p "${WG_CONF_FILE}" "${WG_CONF_FILE}.bak"
    install -m 0600 "${tmp}" "${WG_CONF_FILE}"
}

# =============================================================================
#  FASE 7 — SERVICIO WIREGUARD EN EL HOST (systemd)
# =============================================================================
setup_wg_service() {
    step "Fase 7/7: Servicio WireGuard del host (systemd)"

    # Helper de recarga: si la interfaz ya está levantada, "wg syncconf" aplica
    # altas/bajas de peers en caliente SIN cortar las sesiones existentes. Si
    # no lo está, se arranca con wg-quick (que ejecuta los hooks de red).
    cat >"${RELOAD_HELPER}" <<EOF
#!/usr/bin/env bash
# Generado por wg-manager ${VERSION}. Recarga ${WG_INTERFACE} tras cambios de wireguard-ui.
set -euo pipefail
if ip link show ${WG_INTERFACE} >/dev/null 2>&1; then
    wg syncconf ${WG_INTERFACE} <(wg-quick strip ${WG_INTERFACE})
else
    systemctl restart wg-quick@${WG_INTERFACE}.service
fi
EOF
    chmod 0755 "${RELOAD_HELPER}"

    cat >"${SYSTEMD_DIR}/wg-platform-reload.service" <<EOF
[Unit]
Description=Recarga ${WG_INTERFACE} tras cambios de wireguard-ui
After=network-online.target

[Service]
Type=oneshot
ExecStart=${RELOAD_HELPER}
EOF

    # La unidad .path vigila wg0.conf: cada "Apply Config" del panel dispara
    # la recarga automática sin dar privilegios de red al contenedor.
    cat >"${SYSTEMD_DIR}/wg-platform-reload.path" <<EOF
[Unit]
Description=Vigila ${WG_CONF_FILE} (wireguard-ui)

[Path]
PathChanged=${WG_CONF_FILE}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now wg-platform-reload.path >/dev/null 2>&1
    systemctl enable "wg-quick@${WG_INTERFACE}.service" >/dev/null 2>&1

    # Reinicio completo (no syncconf) para que los hooks nuevos se ejecuten.
    systemctl restart "wg-quick@${WG_INTERFACE}.service" \
        || die "wg-quick@${WG_INTERFACE} no arrancó. Ver: journalctl -u wg-quick@${WG_INTERFACE}"
    systemctl is-active --quiet "wg-quick@${WG_INTERFACE}.service" \
        || die "wg-quick@${WG_INTERFACE} no está activo."

    verify_rules
    success "Interfaz ${WG_INTERFACE} activa con aislamiento y NAT."
}

verify_rules() {
    local rules
    rules="$(iptables -w -S FORWARD; iptables -w -t nat -S POSTROUTING)"
    grep -q -- "-o ${WG_INTERFACE} .*--comment ${RULE_TAG} -j DROP" <<<"${rules}" \
        || die "La regla de aislamiento (DROP ${WG_INTERFACE}->${WG_INTERFACE}) no está cargada."
    grep -q -- "--comment ${RULE_TAG} -j MASQUERADE" <<<"${rules}" \
        || die "La regla MASQUERADE no está cargada."
    success "Reglas iptables verificadas (aislamiento + MASQUERADE)."
}

# =============================================================================
#  PERSISTENCIA: copia del script y fichero de configuración
# =============================================================================
persist_installation() {
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        cat >"${CONFIG_FILE}" <<EOF
# Configuración local de wg-manager (prevalece sobre los valores del script
# y NO se sobrescribe en las auto-actualizaciones).
REPO_URL="${REPO_URL}"
BRANCH="${BRANCH}"
PLATFORM_DIR="${PLATFORM_DIR}"
WG_UI_IMAGE="${WG_UI_IMAGE}"
WGUI_BIND="${WGUI_BIND}"
WGUI_PORT="${WGUI_PORT}"
WG_SUBNET="${WG_SUBNET}"
WG_SERVER_ADDRESS="${WG_SERVER_ADDRESS}"
WG_PORT="${WG_PORT}"
WG_DNS="${WG_DNS}"
PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT}"
WAN_IFACE="${WAN_IFACE}"
ENABLE_UFW="${ENABLE_UFW}"
EOF
        chmod 600 "${CONFIG_FILE}"
        info "Configuración persistida en ${CONFIG_FILE}."
    fi
    if [[ -n "${SCRIPT_PATH}" && "${SCRIPT_PATH}" != "${INSTALL_BIN}" ]]; then
        install -m 0755 "${SCRIPT_PATH}" "${INSTALL_BIN}"
        info "Script instalado en ${INSTALL_BIN} (use: wg-manager update)."
    fi
}

# =============================================================================
#  AUTO-ACTUALIZACIÓN DEL SCRIPT
# =============================================================================
raw_script_url() {
    # https://github.com/OWNER/REPO(.git) -> https://raw.githubusercontent.com/OWNER/REPO/BRANCH/PATH
    local repo="${REPO_URL%/}"
    repo="${repo%.git}"
    repo="${repo#https://github.com/}"
    repo="${repo#http://github.com/}"
    repo="${repo#git@github.com:}"
    printf 'https://raw.githubusercontent.com/%s/%s/%s' "${repo}" "${BRANCH}" "${SCRIPT_REMOTE_PATH}"
}

self_update() {
    step "Auto-actualización del script (v${VERSION})"
    if [[ "${WG_MANAGER_SELF_UPDATED:-0}" == "1" ]]; then
        success "Script ya actualizado en esta ejecución (v${VERSION})."
        return 0
    fi

    local target="${SCRIPT_PATH:-${INSTALL_BIN}}"
    local url tmp remote_version
    url="$(raw_script_url)"
    tmp="$(make_tmp_dir)/wg-manager.sh"

    info "Consultando ${url}"
    if ! curl -fsSL --retry 3 --max-time 30 -H 'Cache-Control: no-cache' -o "${tmp}" "${url}"; then
        warn "No se pudo descargar la versión remota; se continúa con v${VERSION}."
        return 0
    fi

    # Validaciones de integridad antes de sustituir nada.
    head -n1 "${tmp}" | grep -Eq '^#!.*bash' || { warn "Fichero remoto sin shebang bash; se ignora."; return 0; }
    bash -n "${tmp}" || { warn "El script remoto tiene errores de sintaxis; se ignora."; return 0; }
    remote_version="$(sed -n -E 's/^(readonly[[:space:]]+)?VERSION="([^"]+)".*/\2/p' "${tmp}" | head -n1)"
    [[ -n "${remote_version}" ]] || { warn "No se encontró VERSION en el script remoto."; return 0; }

    if ! version_gt "${remote_version}" "${VERSION}"; then
        success "El script está al día (local v${VERSION}, remoto v${remote_version})."
        return 0
    fi

    info "Nueva versión disponible: v${VERSION} -> v${remote_version}"
    if [[ -f "${target}" ]]; then
        cp -p "${target}" "${target}.v${VERSION}.bak"
    fi
    # install + mv: sustitución atómica. El proceso bash actual conserva el
    # inode antiguo abierto, por lo que no lee código mezclado.
    install -m 0755 "${tmp}" "${target}.new"
    mv -f "${target}.new" "${target}"
    chmod +x "${target}"
    if [[ "${target}" != "${INSTALL_BIN}" && -f "${INSTALL_BIN}" ]]; then
        install -m 0755 "${target}" "${INSTALL_BIN}"
    fi
    success "Script actualizado a v${remote_version}. Relanzando..."

    release_lock
    cleanup   # el trap EXIT no se ejecuta con exec
    export WG_MANAGER_SELF_UPDATED=1
    exec "${target}" ${ORIGINAL_ARGS[@]+"${ORIGINAL_ARGS[@]}"}
}

# =============================================================================
#  ACTUALIZACIÓN DE CONTENEDORES
# =============================================================================
update_containers() {
    local force=$1
    step "Actualización de contenedores"
    [[ -f "${COMPOSE_FILE}" ]] || die "No existe ${COMPOSE_FILE}. Ejecute primero: $0 install"
    detect_compose || die "Docker Compose no disponible."

    local running_image latest_image
    info "Descargando últimas imágenes (docker compose pull)..."
    compose pull -q
    latest_image="$(docker image inspect -f '{{.Id}}' "${WG_UI_IMAGE}" 2>/dev/null || true)"
    running_image="$(docker inspect -f '{{.Image}}' "${WG_UI_CONTAINER}" 2>/dev/null || true)"

    if [[ "${force}" == "true" || -z "${running_image}" || "${running_image}" != "${latest_image}" ]]; then
        info "Recreando contenedores (imagen nueva o --force)..."
        compose up -d --force-recreate --remove-orphans
        wait_for_ui || die "wireguard-ui no responde tras la recreación."
        docker image prune -f >/dev/null 2>&1 || true
        success "Contenedores recreados con ${WG_UI_IMAGE} (${latest_image:7:12})."
    else
        success "La imagen ya es la más reciente; no se recrea nada."
    fi
}

# =============================================================================
#  COMANDOS
# =============================================================================
cmd_install() {
    check_root
    check_os
    acquire_lock
    touch "${LOG_FILE}" && chmod 600 "${LOG_FILE}"
    printf '%s%sWireGuard Multi-Tenant Platform — wg-manager v%s%s\n' "${C_BOLD}" "${C_GREEN}" "${VERSION}" "${C_RESET}"

    prepare_os
    install_docker
    setup_sysctl
    setup_firewall
    deploy_stack
    configure_isolation
    setup_wg_service
    persist_installation
    print_summary
}

cmd_update() {
    local force="false" skip_self="false" arg
    for arg in "$@"; do
        case "${arg}" in
            --force)      force="true" ;;
            --skip-self)  skip_self="true" ;;
            *) die "Opción desconocida para update: ${arg}" ;;
        esac
    done
    check_root
    acquire_lock
    touch "${LOG_FILE}" && chmod 600 "${LOG_FILE}"

    [[ "${skip_self}" == "true" ]] || self_update
    detect_compose || die "Docker Compose no disponible. Ejecute: $0 install"
    update_containers "${force}"
    # Re-sincroniza los hooks: si la nueva versión del script cambió las
    # reglas de red, quedan aplicadas sin intervención manual.
    configure_isolation
    setup_wg_service
    print_summary
}

cmd_status() {
    check_root
    detect_compose || die "Docker Compose no disponible."
    step "Contenedores"
    compose ps || true
    step "Interfaz ${WG_INTERFACE}"
    wg show "${WG_INTERFACE}" 2>/dev/null || warn "${WG_INTERFACE} no está activa."
    step "Reglas iptables de wg-manager"
    { iptables -w -S FORWARD; iptables -w -t nat -S POSTROUTING; } | grep -- "${RULE_TAG}" || warn "Sin reglas cargadas."
    step "Servicios"
    systemctl --no-pager --lines=0 status "wg-quick@${WG_INTERFACE}" wg-platform-reload.path || true
}

print_summary() {
    local ip
    ip="$(detect_public_ip 2>/dev/null || echo '<IP-PUBLICA>')"
    printf '\n%s%s════════════════════════════════════════════════════════════%s\n' "${C_GREEN}" "${C_BOLD}" "${C_RESET}"
    printf '%s  Plataforma WireGuard Multi-Tenant operativa (v%s)%s\n' "${C_GREEN}${C_BOLD}" "${VERSION}" "${C_RESET}"
    printf '%s%s════════════════════════════════════════════════════════════%s\n' "${C_GREEN}" "${C_BOLD}" "${C_RESET}"
    printf '  Panel web       : %shttp://%s:%s%s\n' "${C_CYAN}" "${ip}" "${WGUI_PORT}" "${C_RESET}"
    printf '  Endpoint WG     : %s:%s/udp\n' "${ip}" "${WG_PORT}"
    printf '  Subred túnel    : %s (servidor %s)\n' "${WG_SUBNET}" "${WG_SERVER_ADDRESS}"
    printf '  Aislamiento     : tráfico cliente<->cliente BLOQUEADO; salida NAT por %s\n' "${WAN_IFACE}"
    printf '  Stack           : %s\n' "${PLATFORM_DIR}"
    printf '  Actualizar      : %s update\n' "${INSTALL_BIN}"
    printf '\n%s  ⚠  Credenciales por defecto: %s / %s%s\n' "${C_YELLOW}${C_BOLD}" "${WGUI_ADMIN_USER}" "${WGUI_ADMIN_PASS}" "${C_RESET}"
    printf '%s     Cámbielas INMEDIATAMENTE en el panel (Users → Edit).%s\n' "${C_YELLOW}" "${C_RESET}"
    printf '%s     El panel se sirve por HTTP: se recomienda un proxy TLS o restringir%s\n' "${C_YELLOW}" "${C_RESET}"
    printf '%s     el puerto %s/tcp a IPs de administración (ufw allow from <IP>).%s\n\n' "${C_YELLOW}" "${WGUI_PORT}" "${C_RESET}"
}

usage() {
    cat <<EOF
${C_BOLD}wg-manager v${VERSION}${C_RESET} — Plataforma WireGuard Multi-Tenant (wireguard-ui + Docker)

${C_BOLD}Uso:${C_RESET}
  sudo $0 install                Instalación completa (idempotente)
  sudo $0 update [opciones]      Auto-actualiza el script y los contenedores
       --force                   Recrea los contenedores aunque no haya imagen nueva
       --skip-self               No auto-actualiza el script
  sudo $0 status                 Estado de contenedores, interfaz y reglas
  $0 version                     Muestra la versión
  $0 help                        Muestra esta ayuda

${C_BOLD}Configuración:${C_RESET} ${CONFIG_FILE}
${C_BOLD}Repositorio:${C_RESET}   ${REPO_URL} (rama ${BRANCH})
EOF
}

# =============================================================================
#  PARSEO DE ARGUMENTOS / PUNTO DE ENTRADA
# =============================================================================
main() {
    local cmd="${1:-help}"
    [[ $# -gt 0 ]] && shift
    case "${cmd}" in
        install)              cmd_install "$@" ;;
        update)               cmd_update "$@" ;;
        status)               cmd_status "$@" ;;
        version|-v|--version) echo "wg-manager v${VERSION}" ;;
        help|-h|--help)       usage ;;
        *) usage; die "Comando desconocido: ${cmd}" ;;
    esac
}

main "$@"

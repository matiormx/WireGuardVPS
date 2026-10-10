#!/usr/bin/env bash
# =============================================================================
#  wg-manager.sh — Plataforma WireGuard Multi-Tenant (panel propio + Docker)
# -----------------------------------------------------------------------------
#  Despliega y mantiene:
#    * Docker + Docker Compose (plugin v2)
#    * Tuning del kernel (ip_forward + buffers UDP)
#    * Panel web propio (carpeta panel/ del repositorio), construido localmente
#      y ejecutado en Docker con network_mode: host
#    * Interfaz WireGuard del host (wg-quick@wg0) gestionada por systemd
#    * Firewall multi-tenant: cada cliente tiene su red /24; sus dispositivos se
#      ven entre sí, pero el tráfico entre clientes distintos se descarta
#    * Auto-actualización del script (GitHub RAW) y del panel (git pull + build)
#
#  Uso:
#    sudo ./wg-manager.sh install             Instalación completa (idempotente)
#    sudo ./wg-manager.sh update [--force]    Actualiza script, panel y firewall
#    sudo ./wg-manager.sh status              Estado de la plataforma
#    sudo ./wg-manager.sh logs                Logs del panel
#    sudo ./wg-manager.sh reset-admin         Nueva contraseña temporal de admin
#    ./wg-manager.sh help                     Ayuda
#
#  Sistemas soportados: Debian 11+/Ubuntu 20.04+ (apt, systemd, kernel >= 5.6).
# =============================================================================

set -o errexit   # set -e : aborta ante cualquier comando que falle
set -o nounset   # set -u : aborta ante variables no definidas
set -o pipefail  # un pipeline falla si falla cualquiera de sus etapas
set -o errtrace  # set -E : el trap ERR se hereda en funciones y subshells

# -----------------------------------------------------------------------------
# VERSIÓN DEL SCRIPT (se compara con la publicada en GitHub). SemVer.
# -----------------------------------------------------------------------------
readonly VERSION="2.17.0"

# =============================================================================
#  CONFIGURACIÓN EDITABLE
# -----------------------------------------------------------------------------
#  Cualquier valor puede fijarse de forma persistente en /etc/wg-manager.conf
#  (se genera en la instalación y NO se toca en las auto-actualizaciones) o
#  pasarse como variable de entorno en la primera instalación.
# =============================================================================
readonly CONFIG_FILE="/etc/wg-manager.conf"
if [[ -f "${CONFIG_FILE}" ]]; then
    # shellcheck source=/dev/null
    source "${CONFIG_FILE}"
fi

# --- Repositorio (auto-actualización y código del panel) ----------------------
: "${REPO_URL:=https://github.com/matiormx/WireGuardVps}"
: "${BRANCH:=main}"
: "${SCRIPT_REMOTE_PATH:=wg-manager.sh}"
: "${LOCAL_SOURCE:=}"                          # ruta local del repo (desarrollo); vacío = git

# --- Rutas --------------------------------------------------------------------
: "${PLATFORM_DIR:=/opt/wg-platform}"
: "${INSTALL_BIN:=/usr/local/sbin/wg-manager}"
: "${LOG_FILE:=/var/log/wg-manager.log}"

# --- Panel web ----------------------------------------------------------------
: "${PANEL_BIND:=0.0.0.0}"
: "${PANEL_PORT:=${WGUI_PORT:-5000}}"
: "${ADMIN_USER:=${WGUI_ADMIN_USER:-admin}}"
: "${ADMIN_PASS:=${WGUI_ADMIN_PASS:-admin}}"   # se obliga a cambiarla en el primer login
: "${ENABLE_HTTPS:=true}"                      # Caddy: HTTPS automático para los dominios del panel
: "${PANEL_DOMAIN:=}"                          # opcional: dominio inicial (también se configura desde el panel)
: "${ACME_EMAIL:=}"                            # opcional: avisos de Let's Encrypt

# --- WireGuard ----------------------------------------------------------------
: "${WG_INTERFACE:=wg0}"
: "${WG_SUBNET:=10.252.0.0/16}"                # bloque global de la plataforma
: "${WG_SERVER_ADDRESS:=10.252.0.1/16}"        # IP del servidor (bloque 0, reservado)
: "${TENANT_PREFIX:=24}"                       # tamaño de la red de cada cliente
: "${WG_PORT:=51820}"
: "${WG_DNS:=1.1.1.1, 1.0.0.1}"              # DNS de subida del resolver con filtros
: "${DNS_ENABLED:=true}"                       # resolver propio con filtros por cliente
: "${WG_MTU:=1420}"
: "${WG_KEEPALIVE:=25}"

# --- Red del host -------------------------------------------------------------
: "${PUBLIC_ENDPOINT:=}"                       # vacío = autodetección (IP o dominio)
: "${WAN_IFACE:=}"                             # vacío = interfaz de la ruta por defecto
: "${ENABLE_UFW:=true}"

# --- Kernel -------------------------------------------------------------------
readonly SYSCTL_FILE="/etc/sysctl.d/99-wireguard.conf"
readonly NET_BUFFER_SIZE="2500000"

# --- Derivadas (no editar) ----------------------------------------------------
readonly SRC_DIR="${PLATFORM_DIR}/src"
readonly DATA_DIR="${PLATFORM_DIR}/data"
readonly COMPOSE_FILE="${PLATFORM_DIR}/docker-compose.yml"
readonly ENV_FILE="${PLATFORM_DIR}/.env"
readonly CONTAINER="wgp-panel"
readonly WG_CONF_DIR="/etc/wireguard"
readonly WG_CONF_FILE="${WG_CONF_DIR}/${WG_INTERFACE}.conf"
readonly WGP_DIR="${WG_CONF_DIR}/wgp"            # ficheros que el panel comparte con el host
readonly FIREWALL_BIN="/usr/local/sbin/wgp-firewall"
readonly UPDATE_BIN="/usr/local/sbin/wgp-update-run"   # actualizaciones pedidas desde el panel
readonly TENANT_CHAIN="WGP-TENANTS"
readonly EGRESS_CHAIN="WGP-EGRESS"
readonly DNS_CHAIN="WGP-DNS"
readonly PFWD_CHAIN="WGP-PFWD"                     # reenvío de puertos: FORWARD
readonly PDNAT_CHAIN="WGP-PDNAT"                   # reenvío de puertos: DNAT (PREROUTING)
readonly PSNAT_CHAIN="WGP-PSNAT"                   # reenvío de puertos: SNAT hacia wg0
readonly ISNAT_CHAIN="WGP-ISNAT"                   # IPs adicionales: SNAT por dispositivo
readonly RULE_TAG="wg-manager"
readonly SYSTEMD_DIR="/etc/systemd/system"
readonly LOCK_FILE="/var/lock/wg-manager.lock"

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || true)"
[[ -f "${SCRIPT_PATH}" ]] || SCRIPT_PATH=""
readonly ORIGINAL_ARGS=("$@")

DOCKER_COMPOSE=()
TMP_PATHS=()

# =============================================================================
#  SALIDA CON COLORES Y LOGGING
# =============================================================================
if [[ -t 1 ]]; then
    readonly C_RESET=$'\033[0m' C_BOLD=$'\033[1m'
    readonly C_RED=$'\033[1;31m' C_GREEN=$'\033[1;32m'
    readonly C_YELLOW=$'\033[1;33m' C_BLUE=$'\033[1;34m' C_CYAN=$'\033[1;36m'
else
    readonly C_RESET="" C_BOLD="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_CYAN=""
fi

_log_file() {
    { printf '%s [%s] %s\n' "$(date '+%F %T')" "$1" "$2" >>"${LOG_FILE}"; } 2>/dev/null || true
}
info()    { printf '%s[INFO]%s  %s\n' "${C_BLUE}" "${C_RESET}" "$*"; _log_file INFO "$*"; }
warn()    { printf '%s[WARN]%s  %s\n' "${C_YELLOW}" "${C_RESET}" "$*" >&2; _log_file WARN "$*"; }
error()   { printf '%s[ERROR]%s %s\n' "${C_RED}" "${C_RESET}" "$*" >&2; _log_file ERROR "$*"; }
success() { printf '%s[ OK ]%s  %s\n' "${C_GREEN}" "${C_RESET}" "$*"; _log_file OK "$*"; }
step()    { printf '\n%s==> %s%s\n' "${C_CYAN}${C_BOLD}" "$*" "${C_RESET}"; _log_file STEP "$*"; }
die()     { error "$*"; exit 1; }

# =============================================================================
#  TRAPS
# =============================================================================
on_error() {
    error "Fallo en la línea $2 (código $1): $3"
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
    [[ "${EUID}" -eq 0 ]] || die "Se requieren privilegios de root. Ejecute: sudo $0 ${ORIGINAL_ARGS[*]-}"
}

os_release_field() {
    sed -n -E "s/^$1=[\"']?([^\"']*)[\"']?\$/\1/p" /etc/os-release | head -n1
}

check_os() {
    # /etc/os-release se parsea (no se hace "source") porque define su propia
    # variable VERSION, que colisionaría con la VERSION readonly de este script.
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
    mkdir -p "$(dirname "${LOCK_FILE}")"
    exec 9>"${LOCK_FILE}"
    flock -n 9 || die "Ya hay otra instancia de wg-manager en ejecución (${LOCK_FILE})."
}

release_lock() { exec 9>&- || true; }

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
    # La interfaz WAN es la de la ruta por defecto IPv4: por ella sale (con
    # MASQUERADE) el tráfico de los clientes que navegan a través de la VPN.
    if [[ -z "${WAN_IFACE}" ]]; then
        WAN_IFACE="$(ip -4 route show default 2>/dev/null \
            | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit }}')"
    fi
    [[ -n "${WAN_IFACE}" ]] || die "No se pudo detectar la interfaz WAN. Defina WAN_IFACE en ${CONFIG_FILE}."
    ip link show "${WAN_IFACE}" >/dev/null 2>&1 || die "La interfaz WAN '${WAN_IFACE}' no existe."
}

detect_public_ip() {
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

reserved_ports() {
    # Puertos del propio servidor: nunca se pueden reenviar a un dispositivo.
    local p out=" "
    for p in 53 80 443 2019 "${WG_PORT}" "${PANEL_PORT}" $(detect_ssh_ports); do
        [[ "${out}" == *" ${p} "* ]] || out+="${p} "
    done
    printf '%s' "${out# }"
}

random_secret() {
    openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

env_value() {
    # Lee una clave del .env del panel (formato KEY='valor').
    [[ -f "${ENV_FILE}" ]] || return 0
    sed -n -E "s/^$1='?([^']*)'?\$/\1/p" "${ENV_FILE}" | head -n1
}

wait_for_panel() {
    local _
    for _ in $(seq 1 90); do
        if curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:${PANEL_PORT}/healthz" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# =============================================================================
#  FASE 1 — SISTEMA OPERATIVO
# =============================================================================
prepare_os() {
    step "Fase 1/8: Preparación del sistema operativo"
    export DEBIAN_FRONTEND=noninteractive
    info "Actualizando índices de paquetes..."
    apt-get update -qq
    info "Instalando dependencias base..."
    # wireguard-tools en el HOST: wg0 vive en el host (wg-quick@wg0) y el panel
    # sólo le entrega la configuración.
    apt-get install -y -qq --no-install-recommends \
        ca-certificates curl wget gnupg lsb-release \
        iptables ufw git jq openssl iproute2 \
        wireguard-tools >/dev/null
    success "Dependencias instaladas."
}

# =============================================================================
#  FASE 2 — DOCKER
# =============================================================================
install_docker() {
    step "Fase 2/8: Docker Engine y Docker Compose"
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
        info "Instalando docker-compose-plugin..."
        apt-get install -y -qq docker-compose-plugin >/dev/null || die "No se pudo instalar Docker Compose."
        detect_compose || die "Docker Compose sigue sin estar disponible."
    fi
    success "Docker Compose disponible: $("${DOCKER_COMPOSE[@]}" version --short 2>/dev/null || echo ok)"
}

# =============================================================================
#  FASE 3 — KERNEL
# =============================================================================
setup_sysctl() {
    step "Fase 3/8: Tuning del kernel (sysctl)"
    cat >"${SYSCTL_FILE}" <<EOF
# Generado por wg-manager ${VERSION}
#
# ip_forward=1: el host actúa como router. Sin esto los paquetes que entran por
# wg0 (hacia Internet o hacia otro dispositivo del mismo cliente) se descartan
# antes de llegar a la cadena FORWARD.
net.ipv4.ip_forward = 1

# Buffers máximos de socket. WireGuard usa UDP; con muchos peers los valores
# por defecto (~208 KB) provocan descartes en ráfagas. 2.5 MB los absorbe.
net.core.rmem_max = ${NET_BUFFER_SIZE}
net.core.wmem_max = ${NET_BUFFER_SIZE}
EOF
    sysctl -p "${SYSCTL_FILE}" >/dev/null
    if [[ -f /etc/ufw/sysctl.conf ]]; then
        sed -i -E 's|^#?[[:space:]]*net/ipv4/ip_forward[[:space:]]*=.*|net/ipv4/ip_forward=1|' /etc/ufw/sysctl.conf
    fi
    [[ "$(sysctl -n net.ipv4.ip_forward)" == "1" ]] || die "ip_forward no quedó activo."
    success "Parámetros de kernel aplicados (${SYSCTL_FILE})."

    if ! modprobe wireguard 2>/dev/null; then
        ip link add wgtest0 type wireguard 2>/dev/null \
            || die "El kernel no soporta WireGuard (requiere >= 5.6 o wireguard-dkms)."
        ip link del wgtest0 2>/dev/null || true
    fi
    success "Soporte WireGuard en kernel verificado."
}

# =============================================================================
#  FASE 4 — FIREWALL DE ENTRADA (UFW)
# =============================================================================
setup_ufw() {
    step "Fase 4/8: Firewall de entrada (UFW)"
    if [[ "${ENABLE_UFW}" != "true" ]]; then
        warn "ENABLE_UFW=false: abra manualmente ${WG_PORT}/udp y ${PANEL_PORT}/tcp."
        return 0
    fi
    # UFW sólo gobierna INPUT (servicios del host). El reenvío de los túneles
    # lo controlan las reglas de wgp-firewall en la cabeza de FORWARD; la
    # política DEFAULT_FORWARD_POLICY="DROP" de UFW queda como red de seguridad.
    local p
    for p in $(detect_ssh_ports); do
        ufw allow "${p}/tcp" comment 'SSH' >/dev/null
        info "Permitido SSH en ${p}/tcp (anti-bloqueo)."
    done
    ufw allow "${WG_PORT}/udp" comment 'WireGuard' >/dev/null
    # El puerto directo del panel queda abierto para el primer acceso por IP;
    # al activar «Forzar HTTPS» en Ajustes, el panel lo redirige al dominio.
    ufw allow "${PANEL_PORT}/tcp" comment 'WireGuard panel' >/dev/null
    if [[ "${ENABLE_HTTPS}" == "true" ]]; then
        # 80/tcp: emisión y renovación de certificados (ACME) y redirección a HTTPS.
        ufw allow 80/tcp comment 'HTTP (ACME)' >/dev/null
        ufw allow 443/tcp comment 'HTTPS panel' >/dev/null
        ufw allow 443/udp comment 'HTTP/3 panel' >/dev/null
    fi
    ufw --force enable >/dev/null
    success "UFW activo: SSH, ${WG_PORT}/udp, ${PANEL_PORT}/tcp$([[ "${ENABLE_HTTPS}" == "true" ]] && echo ", 80/tcp y 443") permitidos."
}

# =============================================================================
#  FASE 5 — CÓDIGO DEL PANEL
# =============================================================================
fetch_source() {
    step "Fase 5/8: Código del panel (${REPO_URL} @ ${BRANCH})"
    install -d -m 0755 "${PLATFORM_DIR}"
    if [[ -n "${LOCAL_SOURCE}" ]]; then
        [[ -d "${LOCAL_SOURCE}/panel" ]] || die "LOCAL_SOURCE=${LOCAL_SOURCE} no contiene panel/"
        rm -rf "${SRC_DIR}"
        mkdir -p "${SRC_DIR}"
        cp -a "${LOCAL_SOURCE}/." "${SRC_DIR}/"
        success "Código copiado desde ${LOCAL_SOURCE}."
        return 0
    fi
    if [[ -d "${SRC_DIR}/.git" ]]; then
        git -C "${SRC_DIR}" remote set-url origin "${REPO_URL}"
        git -C "${SRC_DIR}" fetch --depth 1 origin "${BRANCH}"
        git -C "${SRC_DIR}" checkout -q -B "${BRANCH}" FETCH_HEAD
        git -C "${SRC_DIR}" reset -q --hard FETCH_HEAD
        git -C "${SRC_DIR}" clean -qfdx
    else
        rm -rf "${SRC_DIR}"
        git clone -q --depth 1 --branch "${BRANCH}" "${REPO_URL}" "${SRC_DIR}"
    fi
    [[ -f "${SRC_DIR}/panel/Dockerfile" ]] || die "El repositorio no contiene panel/Dockerfile."
    success "Código en ${SRC_DIR} ($(git -C "${SRC_DIR}" rev-parse --short HEAD))."
}

# =============================================================================
#  FASE 6 — FIREWALL MULTI-TENANT EN EL HOST
# -----------------------------------------------------------------------------
#  Esquema de reglas (insertadas en la CABEZA de FORWARD, antes que Docker/UFW):
#
#   FORWARD #1  -i wg0 -o wg0                     -> WGP-TENANTS
#   FORWARD #2  -i wg0 -o WAN -s SUBNET           -> ACCEPT    (salida a Internet)
#   FORWARD #3  -i WAN -o wg0 -d SUBNET  REL,EST  -> ACCEPT    (sólo respuestas)
#   nat/POSTROUTING  -s SUBNET -o WAN             -> MASQUERADE
#
#   INPUT    #1/#2  -i wg0 -d 10.252.0.1 udp/tcp 53  -> ACCEPT   (resolver con filtros)
#   FORWARD  -i wg0 -o WAN                     -> WGP-EGRESS (antes del ACCEPT de salida)
#   nat/PREROUTING  -i wg0                     -> WGP-DNS
#
#   WGP-DNS / WGP-EGRESS (por cada cliente con filtros activos, wgp/dns.list):
#     DNS (53) a cualquier servidor -> DNAT al resolver 10.252.0.1:53, de modo
#     que el filtro se aplica aunque el dispositivo tenga otro DNS configurado;
#     DNS-over-TLS/QUIC (853) -> REJECT, para que no se pueda saltar el filtro.
#
#   WGP-TENANTS (una regla por cliente activo, regenerada por el panel):
#     -s 10.252.N.0/24 -d 10.252.N.0/24 -> ACCEPT   (LAN privada del cliente N)
#     ...
#     -j DROP                                       (todo lo demás: entre clientes)
#
#  Un paquete de un dispositivo a otro entra por wg0 y vuelve a salir por wg0,
#  así que TODO el tráfico entre peers pasa por WGP-TENANTS: sólo se acepta si
#  origen y destino pertenecen a la misma red de cliente. La suplantación de IP
#  no es posible: WireGuard descarta cualquier paquete de un peer cuyo origen no
#  esté en su AllowedIPs (/32).
#
#  El panel (contenedor) sólo escribe la lista de redes en wgp/tenants.list; el
#  host valida cada línea y construye él mismo las reglas, de modo que el
#  contenedor nunca inyecta reglas iptables arbitrarias.
# =============================================================================
install_firewall_helper() {
    step "Fase 6/8: Firewall multi-tenant del host"
    detect_wan_iface
    install -d -m 0700 "${WG_CONF_DIR}"
    install -d -m 0755 "${WGP_DIR}"
    # Puertos que un reenvío nunca puede ocupar (servicios del propio servidor).
    local reserved
    reserved="$(reserved_ports)"

    cat >"${FIREWALL_BIN}" <<EOF
#!/usr/bin/env bash
# Generado por wg-manager ${VERSION}. No editar: se regenera en cada install/update.
#   wgp-firewall up <iface>     PostUp de wg-quick: reglas base + cadena de clientes
#   wgp-firewall down <iface>   PostDown de wg-quick: retira todo
#   wgp-firewall sync           Regenera las cadenas desde ${WGP_DIR}/{tenants,dns,forwards}.list
#   wgp-firewall apply          sync + arranca wg-quick@${WG_INTERFACE} si está parado
set -euo pipefail

SUBNET="${WG_SUBNET}"
WAN="${WAN_IFACE}"
IFACE_DEFAULT="${WG_INTERFACE}"
SERVER_IP="${WG_SERVER_ADDRESS%/*}"
LIST="${WGP_DIR}/tenants.list"
DNS_LIST="${WGP_DIR}/dns.list"
FWD_LIST="${WGP_DIR}/forwards.list"
EXITS_LIST="${WGP_DIR}/exits.list"
EXIT_ROUTES="${WGP_DIR}/exit_routes.list"
IPS_LIST="${WGP_DIR}/ips.list"
IP_ROUTES="${WGP_DIR}/ip_routes.list"
IPS_STATE="/var/lib/wgp-firewall/ips.added"
RESERVED=" ${reserved} "
CHAIN="${TENANT_CHAIN}"
EGRESS="${EGRESS_CHAIN}"
DNSCHAIN="${DNS_CHAIN}"
PFWD="${PFWD_CHAIN}"
PDNAT="${PDNAT_CHAIN}"
PSNAT="${PSNAT_CHAIN}"
ISNAT="${ISNAT_CHAIN}"
TAG="${RULE_TAG}"
EOF
    cat >>"${FIREWALL_BIN}" <<'EOF'

ipt() { iptables -w "$@"; }

# rule_specs IFACE -> una regla por línea: "tabla|cadena|posición|argumentos"
rule_specs() {
    local i=$1 c="-m comment --comment ${TAG}"
    printf '%s\n' \
        "filter|INPUT|1|-i ${i} -d ${SERVER_IP} -p udp --dport 53 ${c} -j ACCEPT" \
        "filter|INPUT|2|-i ${i} -d ${SERVER_IP} -p tcp --dport 53 ${c} -j ACCEPT" \
        "filter|FORWARD|1|-i ${i} -o ${i} ${c} -j ${CHAIN}" \
        "filter|FORWARD|2|-i ${i} -o ${WAN} ${c} -j ${EGRESS}" \
        "filter|FORWARD|3|-i ${i} -o ${WAN} -s ${SUBNET} ${c} -j ACCEPT" \
        "filter|FORWARD|4|-i ${WAN} -o ${i} -d ${SUBNET} -m conntrack --ctstate RELATED,ESTABLISHED ${c} -j ACCEPT" \
        "filter|FORWARD|5|-i ${WAN} -o ${i} ${c} -j ${PFWD}" \
        "filter|FORWARD|6|-i ${i} -o ${WAN} -m conntrack --ctstate RELATED,ESTABLISHED ${c} -j ACCEPT" \
        "filter|FORWARD|7|-i ${i} -o wgx+ ${c} -j ${EGRESS}" \
        "filter|FORWARD|8|-i ${i} -o wgx+ -s ${SUBNET} ${c} -j ACCEPT" \
        "filter|FORWARD|9|-i wgx+ -o ${i} -d ${SUBNET} -m conntrack --ctstate RELATED,ESTABLISHED ${c} -j ACCEPT" \
        "nat|PREROUTING|1|-i ${i} ${c} -j ${DNSCHAIN}" \
        "nat|PREROUTING|2|-i ${WAN} -m addrtype --dst-type LOCAL ${c} -j ${PDNAT}" \
        "nat|POSTROUTING|1|-o ${WAN} ${c} -j ${ISNAT}" \
        "nat|POSTROUTING|2|-s ${SUBNET} -o ${WAN} ${c} -j MASQUERADE" \
        "nat|POSTROUTING|3|-o ${i} ${c} -j ${PSNAT}"
}

valid_cidr() {
    local cidr=$1 ip pfx o
    [[ "${cidr}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]{1,2})$ ]] || return 1
    ip=${cidr%/*}; pfx=${cidr#*/}
    (( 10#${pfx} >= 8 && 10#${pfx} <= 30 )) || return 1
    IFS=. read -r -a o <<<"${ip}"
    for x in "${o[@]}"; do (( 10#${x} <= 255 )) || return 1; done
}

# read_nets FICHERO -> redes válidas, una por línea (las inválidas se registran y se ignoran)
read_nets() {
    local file=$1 net
    [[ -f "${file}" ]] || return 0
    while IFS= read -r net || [[ -n "${net}" ]]; do
        net="${net//[[:space:]]/}"
        [[ -z "${net}" ]] && continue
        if valid_cidr "${net}"; then
            echo "${net}"
        else
            logger -t wgp-firewall "Línea ignorada en ${file}: ${net}" || true
        fi
    done <"${file}"
}

valid_ip() {
    local o x
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r -a o <<<"$1"
    for x in "${o[@]}"; do (( 10#${x} <= 255 )) || return 1; done
}

valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

# read_forwards FICHERO -> "proto puerto_publico ip_destino puerto_destino" válidos
read_forwards() {
    local file=$1 proto pport dest dport extra
    [[ -f "${file}" ]] || return 0
    while read -r proto pport dest dport extra || [[ -n "${proto}" ]]; do
        [[ -z "${proto}" ]] && continue
        if [[ "${proto}" =~ ^(tcp|udp)$ ]] && valid_port "${pport}" && valid_ip "${dest}" \
            && valid_port "${dport}" && [[ -z "${extra}" ]] && [[ "${RESERVED}" != *" $((10#${pport})) "* ]]; then
            echo "${proto} $((10#${pport})) ${dest} $((10#${dport}))"
        else
            logger -t wgp-firewall "Reenvío ignorado en ${file}: ${proto} ${pport} ${dest} ${dport} ${extra}" || true
        fi
    done <"${file}"
}

ensure_chains() {
    ipt -N "${CHAIN}" 2>/dev/null || true
    ipt -N "${EGRESS}" 2>/dev/null || true
    ipt -N "${PFWD}" 2>/dev/null || true
    ipt -t nat -N "${DNSCHAIN}" 2>/dev/null || true
    ipt -t nat -N "${PDNAT}" 2>/dev/null || true
    ipt -t nat -N "${PSNAT}" 2>/dev/null || true
    ipt -t nat -N "${ISNAT}" 2>/dev/null || true
}

# --- IPs adicionales (p. ej. IPs de otros países de OVH) ----------------------
# ips.list: una IP por línea; se añade como /32 a la interfaz WAN (y se quita
# cuando el panel la da de baja, sólo si la añadió este script).
# ip_routes.list: "IP_dispositivo IP_adicional" -> SNAT con esa IP de origen.
ip_on_host() { ip -4 -o addr show 2>/dev/null | awk '{print $4}' | grep -qx "$1/[0-9]*"; }

sync_ips() {
    local addr state=() wanted=() kept=()
    install -d -m 0755 "$(dirname "${IPS_STATE}")"
    [[ -f "${IPS_STATE}" ]] && mapfile -t state <"${IPS_STATE}"
    if [[ -f "${IPS_LIST}" ]]; then
        while read -r addr _ || [[ -n "${addr}" ]]; do
            [[ -z "${addr}" ]] && continue
            if ! valid_ip "${addr}"; then
                logger -t wgp-firewall "IP adicional ignorada: ${addr}" || true
                continue
            fi
            wanted+=("${addr}")
            if ! ip_on_host "${addr}"; then
                if ip addr add "${addr}/32" dev "${WAN}" 2>/dev/null; then
                    kept+=("${addr}")
                else
                    logger -t wgp-firewall "No se pudo añadir ${addr} a ${WAN}" || true
                fi
            elif printf '%s\n' "${state[@]}" | grep -qx "${addr}"; then
                kept+=("${addr}")   # ya la habíamos añadido nosotros
            fi
        done <"${IPS_LIST}"
    fi
    for addr in "${state[@]}"; do
        [[ -n "${addr}" ]] || continue
        printf '%s\n' "${wanted[@]}" | grep -qx "${addr}" && continue
        ip addr del "${addr}/32" dev "${WAN}" 2>/dev/null || true
    done
    printf '%s\n' "${kept[@]}" >"${IPS_STATE}"
}

# read_groups FICHERO -> un grupo por línea (red del cliente + LAN de sus routers),
# sólo con las redes válidas. Las redes de un mismo grupo se ven entre sí.
read_groups() {
    local file=$1 line net group
    [[ -f "${file}" ]] || return 0
    while IFS= read -r line || [[ -n "${line}" ]]; do
        group=""
        for net in ${line}; do
            if valid_cidr "${net}"; then
                group+="${net},"
            else
                logger -t wgp-firewall "Red ignorada en ${file}: ${net}" || true
            fi
        done
        if [[ -n "${group}" ]]; then
            echo "${group%,}"
        fi
    done <"${file}"
}

sync_tenants() {
    ensure_chains
    local net src dst group c="-m comment --comment ${TAG}" groups dns fwds proto pport dest dport dev_ip extra_ip isnat=""
    sync_ips
    if [[ -f "${IP_ROUTES}" ]]; then
        while read -r dev_ip extra_ip _ || [[ -n "${dev_ip}" ]]; do
            [[ -z "${dev_ip}" ]] && continue
            if valid_ip "${dev_ip}" && valid_ip "${extra_ip}" && ip_on_host "${extra_ip}"; then
                isnat+="-A ${ISNAT} -s ${dev_ip}/32 ${c} -j SNAT --to-source ${extra_ip}"$'\n'
            else
                logger -t wgp-firewall "Salida por IP ignorada: ${dev_ip} ${extra_ip}" || true
            fi
        done <"${IP_ROUTES}"
    fi
    groups="$(read_groups "${LIST}")"
    dns="$(read_nets "${DNS_LIST}")"
    fwds="$(read_forwards "${FWD_LIST}")"
    {
        # Con --noflush, declarar una cadena la vacía: el cambio es atómico.
        echo "*filter"
        echo ":${CHAIN} - [0:0]"
        echo ":${EGRESS} - [0:0]"
        echo ":${PFWD} - [0:0]"
        for group in ${groups}; do
            for src in ${group//,/ }; do
                for dst in ${group//,/ }; do
                    echo "-A ${CHAIN} -s ${src} -d ${dst} ${c} -j ACCEPT"
                done
            done
        done
        echo "-A ${CHAIN} ${c} -j DROP"
        for net in ${dns}; do
            echo "-A ${EGRESS} -s ${net} -p tcp --dport 853 ${c} -j REJECT --reject-with tcp-reset"
            echo "-A ${EGRESS} -s ${net} -p udp --dport 853 ${c} -j REJECT"
        done
        # Reenvío de puertos: sólo las conexiones redirigidas por WGP-PDNAT.
        while read -r proto pport dest dport; do
            [[ -n "${proto}" ]] || continue
            echo "-A ${PFWD} -d ${dest} -p ${proto} --dport ${dport} -m conntrack --ctstate DNAT ${c} -j ACCEPT"
        done <<<"${fwds}"
        echo "COMMIT"
        echo "*nat"
        echo ":${DNSCHAIN} - [0:0]"
        echo ":${PDNAT} - [0:0]"
        echo ":${PSNAT} - [0:0]"
        echo ":${ISNAT} - [0:0]"
        printf '%s' "${isnat}"
        # SNAT a la IP del servidor: la respuesta vuelve siempre por el túnel,
        # aunque el dispositivo sólo enrute la red privada por WireGuard.
        while read -r proto pport dest dport; do
            [[ -n "${proto}" ]] || continue
            echo "-A ${PDNAT} -p ${proto} --dport ${pport} ${c} -j DNAT --to-destination ${dest}:${dport}"
            echo "-A ${PSNAT} -d ${dest} -p ${proto} --dport ${dport} -m conntrack --ctstate DNAT ${c} -j SNAT --to-source ${SERVER_IP}"
        done <<<"${fwds}"
        for net in ${dns}; do
            echo "-A ${DNSCHAIN} -s ${net} ! -d ${SERVER_IP} -p udp --dport 53 ${c} -j DNAT --to-destination ${SERVER_IP}:53"
            echo "-A ${DNSCHAIN} -s ${net} ! -d ${SERVER_IP} -p tcp --dport 53 ${c} -j DNAT --to-destination ${SERVER_IP}:53"
        done
        echo "COMMIT"
    } | iptables-restore -w --noflush
    logger -t wgp-firewall "Sincronizado: $(wc -w <<<"${groups}") clientes, $(wc -w <<<"${dns}") con filtrado DNS, $(grep -c . <<<"${fwds}") puertos" || true
}

# --- Salidas por país -----------------------------------------------------------
# exits.list: "wgxN TABLA" por cada servidor de salida (el panel escribe
# /etc/wireguard/wgxN.conf con Table = off). exit_routes.list: "IP wgxN" por
# dispositivo. Cada dispositivo con salida usa la tabla de su túnel para todo
# lo que no es la red privada (regla suppress_prefixlength 0 sobre main).
EXIT_PREF=1100
EXIT_MAIN_PREF=1000

sync_exits() {
    local iface table ip dev any=0
    declare -A tables=()
    if [[ -f "${EXITS_LIST}" ]]; then
        while read -r iface table _ || [[ -n "${iface}" ]]; do
            [[ -z "${iface}" ]] && continue
            if [[ ! "${iface}" =~ ^wgx[0-9]{1,3}$ || ! "${table}" =~ ^[0-9]{3,4}$ ]]; then
                logger -t wgp-firewall "Salida ignorada: ${iface} ${table}" || true
                continue
            fi
            tables[${iface}]=${table}
            if [[ -f "/etc/wireguard/${iface}.conf" ]]; then
                if ip link show "${iface}" >/dev/null 2>&1; then
                    wg syncconf "${iface}" <(wg-quick strip "${iface}") 2>/dev/null \
                        || logger -t wgp-firewall "No se pudo actualizar ${iface}" || true
                else
                    systemctl enable "wg-quick@${iface}" >/dev/null 2>&1 || true
                    # En segundo plano: su PostUp vuelve a llamar a este script.
                    systemctl start --no-block "wg-quick@${iface}" >/dev/null 2>&1 || true
                fi
            fi
            if ip link show "${iface}" >/dev/null 2>&1; then
                any=1
                sysctl -qw "net.ipv4.conf.${iface}.rp_filter=2" 2>/dev/null || true
                ip route replace default dev "${iface}" table "${table}"
            fi
        done <"${EXITS_LIST}"
    fi
    # Túneles de salida dados de baja en el panel.
    for iface in /etc/wireguard/wgx*.conf; do
        [[ -e "${iface}" ]] || continue
        iface=$(basename "${iface}" .conf)
        [[ -n "${tables[${iface}]:-}" ]] && continue
        systemctl disable --now "wg-quick@${iface}" >/dev/null 2>&1 || true
    done
    while ip rule del pref "${EXIT_PREF}" 2>/dev/null; do :; done
    while ip rule del pref "${EXIT_MAIN_PREF}" 2>/dev/null; do :; done
    (( any )) || return 0
    # Con salidas, la respuesta llega por wgxN: rp_filter estricto la descartaría.
    [[ "$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)" != "1" ]] || sysctl -qw net.ipv4.conf.all.rp_filter=2
    ip rule add pref "${EXIT_MAIN_PREF}" lookup main suppress_prefixlength 0
    if [[ -f "${EXIT_ROUTES}" ]]; then
        while read -r ip dev _ || [[ -n "${ip}" ]]; do
            [[ -z "${ip}" ]] && continue
            if valid_ip "${ip}" && [[ -n "${tables[${dev}]:-}" ]] && ip link show "${dev}" >/dev/null 2>&1; then
                ip rule add pref "${EXIT_PREF}" from "${ip}/32" lookup "${tables[${dev}]}"
            fi
        done <"${EXIT_ROUTES}"
    fi
}

up() {
    local iface=${1:-${IFACE_DEFAULT}} table chain pos args
    sync_tenants
    sync_exits
    while IFS='|' read -r table chain pos args; do
        # shellcheck disable=SC2086
        ipt -t "${table}" -C "${chain}" ${args} 2>/dev/null || ipt -t "${table}" -I "${chain}" "${pos}" ${args}
    done < <(rule_specs "${iface}")
}

down() {
    local iface=${1:-${IFACE_DEFAULT}} table chain pos args
    while IFS='|' read -r table chain pos args; do
        # shellcheck disable=SC2086
        while ipt -t "${table}" -D "${chain}" ${args} 2>/dev/null; do :; done
    done < <(rule_specs "${iface}")
    ipt -F "${CHAIN}" 2>/dev/null || true
    ipt -X "${CHAIN}" 2>/dev/null || true
    ipt -F "${EGRESS}" 2>/dev/null || true
    ipt -X "${EGRESS}" 2>/dev/null || true
    ipt -F "${PFWD}" 2>/dev/null || true
    ipt -X "${PFWD}" 2>/dev/null || true
    local t
    for t in "${DNSCHAIN}" "${PDNAT}" "${PSNAT}" "${ISNAT}"; do
        ipt -t nat -F "${t}" 2>/dev/null || true
        ipt -t nat -X "${t}" 2>/dev/null || true
    done
    while ip rule del pref "${EXIT_PREF}" 2>/dev/null; do :; done
    while ip rule del pref "${EXIT_MAIN_PREF}" 2>/dev/null; do :; done
}

apply() {
    sync_tenants
    sync_exits
    if [[ -s "/etc/wireguard/${IFACE_DEFAULT}.conf" ]] && ! systemctl is-active --quiet "wg-quick@${IFACE_DEFAULT}"; then
        systemctl start "wg-quick@${IFACE_DEFAULT}" || true
    fi
}

case "${1:-}" in
    up)    up "${2:-}" ;;
    down)  down "${2:-}" ;;
    sync)  sync_tenants; sync_exits ;;
    apply) apply ;;
    *) echo "Uso: $0 {up|down|sync|apply} [iface]" >&2; exit 2 ;;
esac
EOF
    chmod 0755 "${FIREWALL_BIN}"
    bash -n "${FIREWALL_BIN}"

    # El panel escribe wgp/apply.stamp tras cada cambio; esta unidad .path lo
    # detecta y el host regenera la cadena de clientes (y levanta wg0 si hace falta).
    cat >"${SYSTEMD_DIR}/wgp-apply.service" <<EOF
[Unit]
Description=Sincroniza el firewall multi-tenant de WireGuard
After=network-online.target

[Service]
Type=oneshot
ExecStart=${FIREWALL_BIN} apply
EOF
    cat >"${SYSTEMD_DIR}/wgp-apply.path" <<EOF
[Unit]
Description=Vigila los cambios del panel WireGuard

[Path]
PathChanged=${WGP_DIR}/apply.stamp

[Install]
WantedBy=multi-user.target
EOF

    # Limpieza de la versión 1.x (wireguard-ui).
    if [[ -f "${SYSTEMD_DIR}/wg-platform-reload.path" ]]; then
        systemctl disable --now wg-platform-reload.path >/dev/null 2>&1 || true
        rm -f "${SYSTEMD_DIR}/wg-platform-reload.path" "${SYSTEMD_DIR}/wg-platform-reload.service" \
              /usr/local/sbin/wg-platform-reload
        info "Unidades de wireguard-ui (v1) eliminadas."
    fi

    install_update_runner

    systemctl daemon-reload
    systemctl enable --now wgp-apply.path >/dev/null 2>&1
    systemctl enable --now wgp-update.path >/dev/null 2>&1
    success "wgp-firewall instalado (WAN=${WAN_IFACE}, subred ${WG_SUBNET})."
}

# Actualizaciones desde el panel: el panel (contenedor) sólo puede escribir
# wgp/update.request; el host lo detecta (unidad .path) y ejecuta siempre el
# mismo comando, «wg-manager update», guardando el estado y el registro en wgp/.
install_update_runner() {
    # Se escribe aparte y se sustituye con mv: este mismo script se regenera
    # durante la actualización que está ejecutando (bash lee el fichero sobre la marcha).
    local tmp="${UPDATE_BIN}.new"
    cat >"${tmp}" <<EOF
#!/usr/bin/env bash
# Generado por wg-manager ${VERSION}. No editar: se regenera en cada install/update.
set -uo pipefail
DIR="${WGP_DIR}"
WGM="\${WGM_BIN:-${INSTALL_BIN}}"
EOF
    cat >>"${tmp}" <<'EOF'
STATUS="${DIR}/update.status"
LOG="${DIR}/update.log"
exec 8>/run/wgp-update.lock
flock -n 8 || exit 0            # ya hay una actualización en marcha
write_status() { printf '%s\n' "$1" >"${STATUS}.tmp" && chmod 0644 "${STATUS}.tmp" && mv -f "${STATUS}.tmp" "${STATUS}"; }
started=$(date +%s)
write_status "{\"state\": \"running\", \"started_at\": ${started}}"
{
    echo "== $(date '+%Y-%m-%d %H:%M:%S') Actualización solicitada desde el panel"
    "${WGM}" update
} >"${LOG}" 2>&1 </dev/null
rc=$?
chmod 0640 "${LOG}" 2>/dev/null || true
version=$("${WGM}" version 2>/dev/null | awk '{print $2}')
state="done"
[[ ${rc} -eq 0 ]] || state="failed"
write_status "{\"state\": \"${state}\", \"started_at\": ${started}, \"finished_at\": $(date +%s), \"exit_code\": ${rc}, \"version\": \"${version#v}\"}"
logger -t wgp-update "Actualización desde el panel: ${state} (código ${rc})" || true
exit 0
EOF
    chmod 0755 "${tmp}"
    bash -n "${tmp}"
    mv -f "${tmp}" "${UPDATE_BIN}"
    cat >"${SYSTEMD_DIR}/wgp-update.service" <<EOF
[Unit]
Description=Actualiza la plataforma WireGuard a petición del panel
After=network-online.target docker.service

[Service]
Type=oneshot
ExecStart=${UPDATE_BIN}
TimeoutStartSec=45min
EOF
    cat >"${SYSTEMD_DIR}/wgp-update.path" <<EOF
[Unit]
Description=Vigila las peticiones de actualización del panel

[Path]
PathChanged=${WGP_DIR}/update.request

[Install]
WantedBy=multi-user.target
EOF
}

# version.json: lo que el panel muestra en Ajustes › Actualizaciones.
write_version_info() {
    local commit=""
    [[ -d "${SRC_DIR}/.git" ]] && commit="$(git -C "${SRC_DIR}" rev-parse --short HEAD 2>/dev/null || true)"
    local os_name hostname_
    os_name="$(os_release_field PRETTY_NAME 2>/dev/null || true)"
    hostname_="$(hostname -f 2>/dev/null || hostname)"
    install -d -m 0755 "${WGP_DIR}"
    printf '{"version": "%s", "commit": "%s", "updated_at": %s, "updater": 1, "branch": "%s", "os": "%s", "hostname": "%s"}\n' \
        "${VERSION}" "${commit}" "$(date +%s)" "${BRANCH}" "${os_name//\"/}" "${hostname_//\"/}" >"${WGP_DIR}/version.json"
    chmod 0644 "${WGP_DIR}/version.json"
}

# =============================================================================
#  FASE 7 — DESPLIEGUE DEL PANEL
# =============================================================================
deploy_panel() {
    step "Fase 7/8: Despliegue del panel en ${PLATFORM_DIR}"
    local endpoint session_secret
    endpoint="$(detect_public_ip)" || die "No se pudo determinar la IP pública. Defina PUBLIC_ENDPOINT en ${CONFIG_FILE}."
    info "Endpoint público de WireGuard: ${endpoint}:${WG_PORT}"

    install -d -m 0700 "${DATA_DIR}"

    # Migración desde v1: wireguard-ui generó otro wg0.conf con otras claves.
    if [[ -f "${WG_CONF_FILE}" ]] && ! grep -q "Generado por el panel WireGuard Multi-Tenant" "${WG_CONF_FILE}"; then
        cp -p "${WG_CONF_FILE}" "${WG_CONF_FILE}.pre-panel.bak"
        warn "Se ha guardado el wg0.conf anterior en ${WG_CONF_FILE}.pre-panel.bak (será reemplazado)."
    fi

    session_secret="$(env_value SESSION_SECRET)"
    [[ -n "${session_secret}" ]] || session_secret="$(random_secret)"

    [[ -z "${PANEL_DOMAIN}" ]] || check_domain_dns "${endpoint}"

    umask 077
    cat >"${ENV_FILE}" <<EOF
# Generado por wg-manager ${VERSION}. Para cambiar valores edite ${CONFIG_FILE}
# y ejecute: wg-manager update
PANEL_BIND='${PANEL_BIND}'
PANEL_PORT='${PANEL_PORT}'
PANEL_DOMAIN='${PANEL_DOMAIN}'
TRUST_PROXY='true'
SESSION_SECRET='${session_secret}'
ADMIN_USER='${ADMIN_USER}'
ADMIN_PASSWORD='${ADMIN_PASS}'
DATA_DIR='/data'
WG_CONF_DIR='${WG_CONF_DIR}'
WG_INTERFACE='${WG_INTERFACE}'
WG_SUBNET='${WG_SUBNET}'
WG_SERVER_ADDRESS='${WG_SERVER_ADDRESS}'
TENANT_PREFIX='${TENANT_PREFIX}'
WG_PORT='${WG_PORT}'
WG_ENDPOINT='${endpoint}'
WG_DNS='${WG_DNS}'
WG_MTU='${WG_MTU}'
WG_KEEPALIVE='${WG_KEEPALIVE}'
FIREWALL_HOOK='${FIREWALL_BIN}'
DNS_ENABLED='${DNS_ENABLED}'
CADDY_ADMIN='$([[ "${ENABLE_HTTPS}" == "true" ]] && echo "http://127.0.0.1:2019")'
RESERVED_PORTS='$(reserved_ports)'
WGP_SCRIPT_URL='$(raw_script_url)'
ACME_EMAIL='${ACME_EMAIL}'
COOKIE_SECURE='false'
LOG_LEVEL='INFO'
EOF
    umask 022
    chmod 600 "${ENV_FILE}"

    # network_mode: host -> el panel escucha en el host y `wg` ve la interfaz wg0.
    # NET_ADMIN sólo para `wg syncconf`/`wg show` (netlink de WireGuard); las
    # reglas iptables las aplica el host (wgp-firewall), no el contenedor.
    cat >"${COMPOSE_FILE}" <<EOF
# Generado por wg-manager ${VERSION}
services:
  panel:
    build:
      context: ./src/panel
    image: wgp-panel:local
    container_name: ${CONTAINER}
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_ADMIN
    env_file:
      - .env
    volumes:
      - ./data:/data
      - ${WG_CONF_DIR}:${WG_CONF_DIR}
      - /etc/localtime:/etc/localtime:ro
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
EOF
    if [[ "${ENABLE_HTTPS}" == "true" ]]; then
        write_caddy_config
        cat >>"${COMPOSE_FILE}" <<EOF

  # Proxy HTTPS con certificados automáticos de Let's Encrypt (on-demand TLS):
  # cualquier dominio dado de alta en el panel obtiene su certificado al visitarlo.
  # El panel envía la configuración completa (panel + servicios publicados) a la
  # API de administración de Caddy (sólo localhost:2019); --resume la conserva
  # entre reinicios.
  caddy:
    image: caddy:2-alpine
    container_name: wgp-caddy
    restart: unless-stopped
    network_mode: host
    command: caddy run --config /etc/caddy/Caddyfile --adapter caddyfile --resume
    volumes:
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - ./caddy/data:/data
      - ./caddy/config:/config
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
EOF
    fi

    compose config -q
    [[ "${DNS_ENABLED}" != "true" ]] || check_dns_port
    info "Construyendo la imagen del panel (puede tardar un par de minutos)..."
    compose build --pull -q
    if [[ "${ENABLE_HTTPS}" == "true" ]]; then
        check_web_ports
        compose pull -q caddy
    fi
    # --remove-orphans retira el contenedor wireguard-ui de la v1 (mismo proyecto).
    compose up -d --remove-orphans
    wait_for_panel || die "El panel no responde en el puerto ${PANEL_PORT}. Ver: docker logs ${CONTAINER}"
    success "Panel en ejecución."
    if [[ "${ENABLE_HTTPS}" == "true" && -n "${PANEL_DOMAIN}" ]]; then
        local _
        for _ in $(seq 1 45); do
            curl -fsS -o /dev/null --max-time 5 "https://${PANEL_DOMAIN}/healthz" 2>/dev/null && break
            sleep 2
        done
        if curl -fsS -o /dev/null --max-time 5 "https://${PANEL_DOMAIN}/healthz" 2>/dev/null; then
            success "HTTPS activo: https://${PANEL_DOMAIN}"
        else
            warn "HTTPS aún no responde. Compruebe que ${PANEL_DOMAIN} apunta a este servidor y vea: docker logs wgp-caddy"
        fi
    fi
}

check_dns_port() {
    # El resolver con filtros escucha en la IP del servidor dentro del túnel
    # (puerto 53). Otro servicio escuchando en 0.0.0.0:53 o en esa IP lo impediría
    # (systemd-resolved usa 127.0.0.53 y no molesta).
    local server_ip="${WG_SERVER_ADDRESS%/*}" busy
    busy="$(ss -H -lnup 2>/dev/null | awk -v ip="${server_ip}" \
        '$4 == "0.0.0.0:53" || $4 == "*:53" || $4 == ip":53" { print $4, $NF }' | grep -v wgp-panel || true)"
    if [[ -n "${busy}" ]]; then
        warn "Otro servicio ocupa el puerto DNS (53): ${busy}"
        warn "El filtrado de navegación no funcionará hasta liberarlo (o desactívelo con DNS_ENABLED=false)."
    fi
}

check_web_ports() {
    # Caddy necesita 80 y 443. Otro servidor web (nginx, apache...) lo impediría.
    local busy
    busy="$(ss -H -ltnp 2>/dev/null | awk '$4 ~ /:(80|443)$/ { print $4, $NF }' | grep -v -e caddy -e wgp-caddy || true)"
    if [[ -n "${busy}" ]]; then
        warn "Los puertos 80/443 están ocupados por otro servicio: ${busy}"
        warn "El HTTPS automático no funcionará hasta liberarlos (o desactívelo con ENABLE_HTTPS=false)."
    fi
}

check_domain_dns() {
    local expected=$1 resolved
    resolved="$(getent ahostsv4 "${PANEL_DOMAIN}" 2>/dev/null | awk 'NR == 1 { print $1 }')"
    if [[ -z "${resolved}" ]]; then
        warn "${PANEL_DOMAIN} no resuelve todavía. Cree un registro A hacia ${expected}; Caddy reintentará el certificado."
    elif is_ipv4 "${expected}" && [[ "${resolved}" != "${expected}" ]]; then
        warn "${PANEL_DOMAIN} apunta a ${resolved}, no a ${expected}. El certificado no se emitirá hasta corregirlo."
    else
        info "DNS correcto: ${PANEL_DOMAIN} -> ${resolved}"
    fi
}

write_caddy_config() {
    # On-demand TLS: antes de pedir un certificado, Caddy pregunta al panel
    # (/internal/tls-ask) si el dominio está dado de alta y apunta aquí.
    install -d -m 0755 "${PLATFORM_DIR}/caddy" "${PLATFORM_DIR}/caddy/data" "${PLATFORM_DIR}/caddy/config"
    {
        printf '{\n'
        [[ -z "${ACME_EMAIL}" ]] || printf '\temail %s\n' "${ACME_EMAIL}"
        printf '\ton_demand_tls {\n\t\task http://127.0.0.1:%s/internal/tls-ask\n\t}\n' "${PANEL_PORT}"
        printf '}\n\n'
        printf 'https:// {\n'
        printf '\ttls {\n\t\ton_demand\n\t}\n'
        printf '\tencode zstd gzip\n'
        printf '\theader Strict-Transport-Security "max-age=31536000"\n'
        printf '\treverse_proxy 127.0.0.1:%s\n' "${PANEL_PORT}"
        printf '}\n\n'
        printf 'http:// {\n'
        printf '\tredir https://{host}{uri} 308\n'
        printf '}\n'
    } >"${PLATFORM_DIR}/caddy/Caddyfile"
}

# =============================================================================
#  FASE 8 — INTERFAZ WIREGUARD
# =============================================================================
start_wireguard() {
    step "Fase 8/8: Interfaz ${WG_INTERFACE}"
    local _
    # El panel genera wg0.conf (claves del servidor + peers) al arrancar.
    for _ in $(seq 1 30); do
        [[ -s "${WG_CONF_FILE}" ]] && grep -q "Generado por el panel" "${WG_CONF_FILE}" && break
        sleep 1
    done
    grep -q "Generado por el panel" "${WG_CONF_FILE}" 2>/dev/null || die "El panel no generó ${WG_CONF_FILE}."

    systemctl enable "wg-quick@${WG_INTERFACE}.service" >/dev/null 2>&1
    if systemctl is-active --quiet "wg-quick@${WG_INTERFACE}.service"; then
        # Ya activa (reinstalación/update): no se reinicia para no cortar a los
        # clientes; se reaplican las reglas (idempotente) y la cadena de clientes.
        "${FIREWALL_BIN}" up "${WG_INTERFACE}"
        info "${WG_INTERFACE} ya estaba activa; reglas reaplicadas sin cortar conexiones."
    else
        # wg-quick lee wg0.conf completo (clave + peers) y su PostUp llama a
        # wgp-firewall up, que crea las reglas base y la cadena de clientes.
        systemctl start "wg-quick@${WG_INTERFACE}.service" \
            || die "wg-quick@${WG_INTERFACE} no arrancó. Ver: journalctl -u wg-quick@${WG_INTERFACE}"
    fi
    systemctl is-active --quiet "wg-quick@${WG_INTERFACE}.service" || die "wg-quick@${WG_INTERFACE} no está activo."
    verify_rules
    success "Interfaz ${WG_INTERFACE} activa con aislamiento entre clientes y NAT."
}

verify_rules() {
    local rules
    rules="$(iptables -w -S FORWARD; iptables -w -S "${TENANT_CHAIN}"; iptables -w -t nat -S POSTROUTING)"
    grep -q -- "-i ${WG_INTERFACE} -o ${WG_INTERFACE} .*-j ${TENANT_CHAIN}" <<<"${rules}" \
        || die "Falta el salto ${WG_INTERFACE}->${WG_INTERFACE} a ${TENANT_CHAIN}."
    grep -q -- "-A ${TENANT_CHAIN} .*-j DROP" <<<"${rules}" || die "Falta el DROP final de ${TENANT_CHAIN}."
    grep -q -- "--comment ${RULE_TAG} -j MASQUERADE" <<<"${rules}" || die "Falta la regla MASQUERADE."
    iptables -w -t nat -S PREROUTING | grep -q -- "-j ${DNS_CHAIN}" || die "Falta el salto a ${DNS_CHAIN}."
    success "Reglas verificadas (aislamiento por cliente + MASQUERADE)."
}

# =============================================================================
#  PERSISTENCIA
# =============================================================================
persist_installation() {
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        cat >"${CONFIG_FILE}" <<EOF
# Configuración local de wg-manager. Prevalece sobre los valores del script y
# NO se sobrescribe en las auto-actualizaciones. Tras editar: wg-manager update
REPO_URL="${REPO_URL}"
BRANCH="${BRANCH}"
PANEL_BIND="${PANEL_BIND}"
PANEL_PORT="${PANEL_PORT}"
PANEL_DOMAIN="${PANEL_DOMAIN}"
ACME_EMAIL="${ACME_EMAIL}"
WG_SUBNET="${WG_SUBNET}"
WG_SERVER_ADDRESS="${WG_SERVER_ADDRESS}"
TENANT_PREFIX="${TENANT_PREFIX}"
WG_PORT="${WG_PORT}"
WG_DNS="${WG_DNS}"
PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT}"
WAN_IFACE="${WAN_IFACE}"
ENABLE_UFW="${ENABLE_UFW}"
EOF
        chmod 600 "${CONFIG_FILE}"
        info "Configuración persistida en ${CONFIG_FILE}."
    fi
    # Claves añadidas en versiones posteriores: se guardan si se pasaron por
    # entorno (p. ej. sudo PANEL_DOMAIN=vpn.ejemplo.com wg-manager update).
    local key
    for key in PANEL_DOMAIN ACME_EMAIL DNS_ENABLED ENABLE_HTTPS; do
        if [[ -n "${!key}" ]] && ! grep -q "^${key}=" "${CONFIG_FILE}"; then
            printf '%s="%s"\n' "${key}" "${!key}" >>"${CONFIG_FILE}"
            info "${key} guardado en ${CONFIG_FILE}."
        fi
    done
    if [[ -n "${SCRIPT_PATH}" && "${SCRIPT_PATH}" != "${INSTALL_BIN}" ]]; then
        install -m 0755 "${SCRIPT_PATH}" "${INSTALL_BIN}"
        info "Script instalado en ${INSTALL_BIN}."
    fi
    write_version_info
}

# =============================================================================
#  AUTO-ACTUALIZACIÓN DEL SCRIPT
# =============================================================================
raw_script_url() {
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
    local target="${SCRIPT_PATH:-${INSTALL_BIN}}" url tmp remote_version
    url="$(raw_script_url)"
    tmp="$(make_tmp_dir)/wg-manager.sh"
    info "Consultando ${url}"
    if ! curl -fsSL --retry 3 --max-time 30 -H 'Cache-Control: no-cache' -o "${tmp}" "${url}"; then
        warn "No se pudo descargar la versión remota; se continúa con v${VERSION}."
        return 0
    fi
    head -n1 "${tmp}" | grep -Eq '^#!.*bash' || { warn "Fichero remoto sin shebang bash; se ignora."; return 0; }
    bash -n "${tmp}" || { warn "El script remoto tiene errores de sintaxis; se ignora."; return 0; }
    remote_version="$(sed -n -E 's/^(readonly[[:space:]]+)?VERSION="([^"]+)".*/\2/p' "${tmp}" | head -n1)"
    [[ -n "${remote_version}" ]] || { warn "No se encontró VERSION en el script remoto."; return 0; }
    if ! version_gt "${remote_version}" "${VERSION}"; then
        success "El script está al día (local v${VERSION}, remoto v${remote_version})."
        return 0
    fi
    info "Nueva versión disponible: v${VERSION} -> v${remote_version}"
    [[ -f "${target}" ]] && cp -p "${target}" "${target}.v${VERSION}.bak"
    # install + mv: sustitución atómica; el bash en curso conserva el inode antiguo.
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
#  COMANDOS
# =============================================================================
banner() {
    printf '%s%sWireGuard Multi-Tenant Platform — wg-manager v%s%s\n' "${C_BOLD}" "${C_GREEN}" "${VERSION}" "${C_RESET}"
}

cmd_install() {
    check_root
    check_os
    acquire_lock
    touch "${LOG_FILE}" && chmod 600 "${LOG_FILE}"
    banner
    prepare_os
    install_docker
    setup_sysctl
    setup_ufw
    fetch_source
    install_firewall_helper
    deploy_panel
    start_wireguard
    persist_installation
    print_summary
}

cmd_update() {
    local force="false" skip_self="false" arg
    for arg in "$@"; do
        case "${arg}" in
            --force)     force="true" ;;
            --skip-self) skip_self="true" ;;
            *) die "Opción desconocida para update: ${arg}" ;;
        esac
    done
    check_root
    acquire_lock
    touch "${LOG_FILE}" && chmod 600 "${LOG_FILE}"
    banner
    [[ "${skip_self}" == "true" ]] || self_update
    if [[ ! -f "${COMPOSE_FILE}" && -f "/etc/wireguard/${EXIT_IFACE}.conf" ]]; then
        success "Nodo de salida: el script está al día (no hay panel que actualizar)."
        return 0
    fi
    detect_compose || die "Docker Compose no disponible. Ejecute: $0 install"
    [[ -f "${COMPOSE_FILE}" ]] || die "No existe ${COMPOSE_FILE}. Ejecute: $0 install"

    setup_sysctl
    fetch_source
    install_firewall_helper
    if [[ "${force}" == "true" ]]; then
        deploy_panel
        compose up -d --force-recreate >/dev/null
        wait_for_panel || die "El panel no responde tras recrearlo."
    else
        # deploy_panel reconstruye la imagen; compose sólo recrea el
        # contenedor si la imagen o la configuración han cambiado.
        deploy_panel
    fi
    start_wireguard
    persist_installation
    print_summary
}

cmd_status() {
    check_root
    detect_compose || die "Docker Compose no disponible."
    step "Panel"
    compose ps || true
    step "Interfaz ${WG_INTERFACE}"
    wg show "${WG_INTERFACE}" 2>/dev/null | head -n 12 || warn "${WG_INTERFACE} no está activa."
    step "Redes de cliente (${TENANT_CHAIN})"
    iptables -w -S "${TENANT_CHAIN}" 2>/dev/null || warn "Cadena ${TENANT_CHAIN} no cargada."
    step "Reglas base"
    { iptables -w -S FORWARD; iptables -w -t nat -S POSTROUTING; } | grep -- "${RULE_TAG}" || warn "Sin reglas cargadas."
    step "Servicios"
    systemctl --no-pager --lines=0 status "wg-quick@${WG_INTERFACE}" wgp-apply.path || true
}

cmd_logs() {
    check_root
    detect_compose || die "Docker Compose no disponible."
    compose logs --tail 200 -f
}

# =============================================================================
#  NODO DE SALIDA (otro país)
# -----------------------------------------------------------------------------
#  Un VPS sencillo (sin panel ni Docker) que da salida a Internet a los
#  dispositivos que la elijan. El servidor principal se conecta a él por un
#  túnel WireGuard propio (wgexit); aquí sólo se hace NAT hacia Internet.
#  El panel genera el token (claves y direcciones del túnel) al darlo de alta.
# =============================================================================
EXIT_IFACE="wgexit"

decode_token() {
    local t=${1//-/+}
    t=${t//_//}
    while (( ${#t} % 4 )); do t+="="; done
    printf '%s' "${t}" | base64 -d 2>/dev/null
}

cmd_exit_node() {
    local token="${1:-}" raw version link_iface exit_key hub_pub exit_addr hub_ip subnet port label
    [[ -n "${token}" ]] || die "Uso: $0 exit-node <token> (cópialo del panel: Ajustes › Salidas por país)"
    check_root
    check_os
    acquire_lock
    touch "${LOG_FILE}" && chmod 600 "${LOG_FILE}"
    banner
    raw="$(decode_token "${token}")" || die "Token no válido."
    IFS='|' read -r version link_iface exit_key hub_pub exit_addr hub_ip subnet port label <<<"${raw}"
    [[ "${version}" == "v1" ]] || die "Token no válido o de otra versión: vuelve a copiarlo del panel."
    [[ "${exit_key}" =~ ^[A-Za-z0-9+/]{43}=$ && "${hub_pub}" =~ ^[A-Za-z0-9+/]{43}=$ ]] || die "Claves del token no válidas."
    [[ "${exit_addr}" =~ ^169\.254\.252\.[0-9]{1,3}/30$ && "${hub_ip}" =~ ^169\.254\.252\.[0-9]{1,3}$ ]] || die "Direcciones del token no válidas."
    [[ "${subnet}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ && "${port}" =~ ^[0-9]{2,5}$ ]] || die "Red o puerto del token no válidos."
    [[ "${link_iface}" =~ ^wgx[0-9]{1,3}$ ]] || die "Token no válido."
    label="${label//[^[:alnum:] ._-]/}"

    step "Nodo de salida «${label}»"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends ca-certificates curl iptables iproute2 wireguard-tools >/dev/null
    setup_sysctl
    detect_wan_iface
    install -d -m 0700 /etc/wireguard
    umask 077
    cat >"/etc/wireguard/${EXIT_IFACE}.conf" <<EOF
# Generado por wg-manager ${VERSION}: nodo de salida «${label}» (${link_iface} en el servidor principal).
[Interface]
Address = ${exit_addr}
ListenPort = ${port}
PrivateKey = ${exit_key}
MTU = ${WG_MTU}
PostUp = iptables -w -t nat -A POSTROUTING -s ${subnet} -o ${WAN_IFACE} -j MASQUERADE; iptables -w -I FORWARD 1 -i %i -o ${WAN_IFACE} -s ${subnet} -j ACCEPT; iptables -w -I FORWARD 2 -i ${WAN_IFACE} -o %i -d ${subnet} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -w -t nat -D POSTROUTING -s ${subnet} -o ${WAN_IFACE} -j MASQUERADE; iptables -w -D FORWARD -i %i -o ${WAN_IFACE} -s ${subnet} -j ACCEPT; iptables -w -D FORWARD -i ${WAN_IFACE} -o %i -d ${subnet} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

[Peer]
# Servidor principal (sólo él puede usar esta salida)
PublicKey = ${hub_pub}
AllowedIPs = ${hub_ip}/32, ${subnet}
EOF
    umask 022
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "${port}/udp" comment 'WireGuard salida' >/dev/null
        info "UFW: permitido ${port}/udp."
    fi
    systemctl enable "wg-quick@${EXIT_IFACE}" >/dev/null 2>&1
    systemctl restart "wg-quick@${EXIT_IFACE}" || die "wg-quick@${EXIT_IFACE} no arrancó. Ver: journalctl -u wg-quick@${EXIT_IFACE}"
    if [[ -n "${SCRIPT_PATH}" && "${SCRIPT_PATH}" != "${INSTALL_BIN}" ]]; then
        install -m 0755 "${SCRIPT_PATH}" "${INSTALL_BIN}"
    fi
    success "Nodo de salida listo: escuchando en ${port}/udp."
    printf '\n  En el panel, la salida «%s» aparecerá conectada en menos de un minuto.\n' "${label}"
    printf '  IP pública de salida: %s\n\n' "$(detect_public_ip 2>/dev/null || echo '?')"
}

cmd_backup() {
    check_root
    docker exec "${CONTAINER}" python -m app.cli backup
}

set_config_value() {
    # Guarda KEY="valor" en la configuración local (reemplaza o añade).
    local key=$1 value=$2
    if grep -q "^${key}=" "${CONFIG_FILE}" 2>/dev/null; then
        sed -i -E "s|^${key}=.*|${key}=\"${value}\"|" "${CONFIG_FILE}"
    else
        printf '%s="%s"\n' "${key}" "${value}" >>"${CONFIG_FILE}"
    fi
}

cmd_restore() {
    local file="${1:-}" net key value changed="false" pass="${WGP_BACKUP_PASSPHRASE:-}"
    [[ -n "${file}" && -f "${file}" ]] || die "Uso: $0 restore <copia.wgpb>"
    check_root
    acquire_lock
    touch "${LOG_FILE}" && chmod 600 "${LOG_FILE}"
    banner
    detect_compose || die "Docker Compose no disponible. Ejecute primero: $0 install"
    [[ -f "${COMPOSE_FILE}" ]] || die "Instale primero la plataforma (${0} install) y después restaure."
    step "Restauración de ${file}"
    if [[ -z "${pass}" ]]; then
        read -r -s -p "Frase de paso de la copia: " pass </dev/tty
        echo
    fi
    export WGP_BACKUP_PASSPHRASE="${pass}"
    install -m 0600 "${file}" "${DATA_DIR}/restore.wgpb"
    # shellcheck disable=SC2329  # se invoca más abajo
    run_cli() { compose run --rm --no-deps -T -e WGP_BACKUP_PASSPHRASE panel python -m app.cli "$@"; }
    if ! run_cli inspect /data/restore.wgpb; then
        rm -f "${DATA_DIR}/restore.wgpb"
        die "No se pudo leer la copia (¿frase de paso correcta?)."
    fi
    net="$(run_cli inspect --env /data/restore.wgpb)"
    # La red debe ser la de la copia: las claves y configuraciones de los
    # dispositivos dependen de ella. Se ajusta la configuración local.
    while IFS='=' read -r key value; do
        [[ "${key}" =~ ^(WG_SUBNET|WG_SERVER_ADDRESS|TENANT_PREFIX|WG_PORT)$ ]] || continue
        [[ "${value}" =~ ^[0-9./]+$ ]] || die "Valor no válido en la copia: ${key}=${value}"
        if [[ "${!key}" != "${value}" ]]; then
            info "${key}: ${!key} -> ${value}"
            set_config_value "${key}" "${value}"
            printf -v "${key}" '%s' "${value}"
            changed="true"
        fi
    done <<<"${net}"
    if [[ -t 0 ]]; then
        local answer
        read -r -p "Se reemplazarán todos los datos actuales del panel. ¿Continuar? [s/N] " answer </dev/tty
        [[ "${answer}" =~ ^[sSyY]$ ]] || { rm -f "${DATA_DIR}/restore.wgpb"; die "Restauración cancelada."; }
    fi
    compose stop panel >/dev/null
    if ! run_cli restore --force /data/restore.wgpb; then
        rm -f "${DATA_DIR}/restore.wgpb"
        compose up -d >/dev/null
        die "La restauración falló; el panel sigue con los datos anteriores."
    fi
    rm -f "${DATA_DIR}/restore.wgpb"
    unset WGP_BACKUP_PASSPHRASE
    [[ "${changed}" == "false" ]] || setup_ufw
    install_firewall_helper
    deploy_panel
    # Clave privada, dirección y puerto del servidor vienen de la copia: hay que
    # recrear la interfaz (los dispositivos reconectan solos en segundos).
    for _ in $(seq 1 30); do
        grep -q "Generado por el panel" "${WG_CONF_FILE}" 2>/dev/null && break
        sleep 1
    done
    systemctl restart "wg-quick@${WG_INTERFACE}.service" \
        || die "wg-quick@${WG_INTERFACE} no arrancó. Ver: journalctl -u wg-quick@${WG_INTERFACE}"
    persist_installation
    success "Copia restaurada."
    printf '  Si el endpoint de WireGuard es un nombre (Ajustes del panel), apúntalo a este servidor:\n'
    printf '  los dispositivos se reconectarán sin tocar nada. Si era la IP del servidor anterior,\n'
    printf '  habrá que reimportar las configuraciones.\n'
    print_summary
}

cmd_reset_admin() {
    check_root
    docker exec "${CONTAINER}" python -m app.cli reset-admin "$@"
}

print_summary() {
    local ip
    detect_wan_iface
    ip="$(detect_public_ip 2>/dev/null || echo '<IP-PUBLICA>')"
    printf '\n%s%s════════════════════════════════════════════════════════════%s\n' "${C_GREEN}" "${C_BOLD}" "${C_RESET}"
    printf '%s  Plataforma WireGuard Multi-Tenant operativa (v%s)%s\n' "${C_GREEN}${C_BOLD}" "${VERSION}" "${C_RESET}"
    printf '%s%s════════════════════════════════════════════════════════════%s\n' "${C_GREEN}" "${C_BOLD}" "${C_RESET}"
    if [[ -n "${PANEL_DOMAIN}" ]]; then
        printf '  Panel web       : %shttps://%s%s  (instalable como app)\n' "${C_CYAN}" "${PANEL_DOMAIN}" "${C_RESET}"
    else
        printf '  Panel web       : %shttp://%s:%s%s\n' "${C_CYAN}" "${ip}" "${PANEL_PORT}" "${C_RESET}"
    fi
    printf '  Endpoint WG     : %s:%s/udp\n' "${ip}" "${WG_PORT}"
    printf '  Subred          : %s (una /%s por cliente; servidor %s)\n' "${WG_SUBNET}" "${TENANT_PREFIX}" "${WG_SERVER_ADDRESS}"
    printf '  Aislamiento     : LAN privada por cliente; tráfico entre clientes BLOQUEADO\n'
    printf '  Salida Internet : NAT por %s\n' "${WAN_IFACE}"
    if [[ "${DNS_ENABLED}" == "true" ]]; then
        printf '  Filtros DNS     : resolver en %s:53 (anuncios, malware, familia por cliente)\n' "${WG_SERVER_ADDRESS%/*}"
    fi
    printf '  Actualizar      : %s update\n' "${INSTALL_BIN}"
    printf '\n%s  ⚠  Acceso inicial: %s / (contraseña de instalación, por defecto "admin")%s\n' "${C_YELLOW}${C_BOLD}" "${ADMIN_USER}" "${C_RESET}"
    printf '%s     El panel obliga a cambiarla en el primer inicio de sesión.%s\n' "${C_YELLOW}" "${C_RESET}"
    if [[ -z "${PANEL_DOMAIN}" && "${ENABLE_HTTPS}" == "true" ]]; then
        printf '%s     HTTPS: configure su dominio en el panel (Ajustes) y, si quiere, active%s\n' "${C_YELLOW}" "${C_RESET}"
        printf '%s     «Forzar HTTPS». Cada cliente puede añadir el suyo desde su Cuenta.%s\n\n' "${C_YELLOW}" "${C_RESET}"
    else
        printf '\n'
    fi
}

usage() {
    cat <<EOF
${C_BOLD}wg-manager v${VERSION}${C_RESET} — Plataforma WireGuard Multi-Tenant

${C_BOLD}Uso:${C_RESET}
  sudo $0 install                Instalación completa (idempotente)
  sudo $0 update [opciones]      Actualiza script, panel (git + build) y firewall
       --force                   Recrea el contenedor aunque no haya cambios
       --skip-self               No auto-actualiza el script
  sudo $0 status                 Estado del panel, interfaz y reglas
  sudo $0 logs                   Logs del panel (Ctrl+C para salir)
  sudo $0 reset-admin [--username U] [--password P]
                                 Contraseña temporal para el administrador
  sudo $0 backup                 Copia cifrada ahora (frase de paso: panel › Ajustes)
  sudo $0 restore <copia.wgpb>   Restaura una copia (p. ej. en un servidor nuevo)
  sudo $0 exit-node <token>      Convierte este VPS en salida por país (token del panel)
  $0 version | help

${C_BOLD}Configuración:${C_RESET} ${CONFIG_FILE}
${C_BOLD}Repositorio:${C_RESET}   ${REPO_URL} (rama ${BRANCH})
EOF
}

main() {
    local cmd="${1:-help}"
    [[ $# -gt 0 ]] && shift
    case "${cmd}" in
        install)              cmd_install "$@" ;;
        update)               cmd_update "$@" ;;
        status)               cmd_status "$@" ;;
        logs)                 cmd_logs "$@" ;;
        reset-admin)          cmd_reset_admin "$@" ;;
        backup)               cmd_backup "$@" ;;
        exit-node)            cmd_exit_node "$@" ;;
        restore)              cmd_restore "$@" ;;
        version|-v|--version) echo "wg-manager v${VERSION}" ;;
        help|-h|--help)       usage ;;
        *) usage; die "Comando desconocido: ${cmd}" ;;
    esac
}

main "$@"

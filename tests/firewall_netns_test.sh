#!/usr/bin/env bash
# Prueba de integración del firewall multi-tenant con tráfico real.
# Requiere root, iproute2, iptables e iputils-ping. Uso: sudo tests/firewall_netns_test.sh
#
# Simula wg0 con namespaces: un "servidor" que enruta y tres dispositivos
# (a1, a2 del cliente 1; b1 del cliente 2) cuyo tráfico entra y sale por wg0,
# igual que en WireGuard. Instala el wgp-firewall real generado por wg-manager.sh.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

NS=(srv a1 a2 b1 inet sw r1 lan1)
netns_cleanup() {
    for p in "${PIDS[@]+"${PIDS[@]}"}"; do kill "$p" 2>/dev/null; done
    for n in "${NS[@]}"; do ip netns del "$n" 2>/dev/null; done
    true
}
netns_cleanup

# Genera /usr/local/sbin/wgp-firewall con la función real del script.
# shellcheck source=/dev/null
source <(sed '$d' "${ROOT}/wg-manager.sh")
set +e
# shellcheck disable=SC2034  # la usa install_firewall_helper
detect_wan_iface() { WAN_IFACE=eth0; }
systemctl() { return 0; }
install_firewall_helper >/dev/null || { echo "install_firewall_helper falló"; exit 1; }
trap - ERR
trap netns_cleanup EXIT   # tras el source, que define sus propios traps
LIST=/etc/wireguard/wgp/tenants.list
DNS_LIST=/etc/wireguard/wgp/dns.list
FWD_LIST=/etc/wireguard/wgp/forwards.list
PIDS=()

for n in "${NS[@]}"; do ip netns add "$n"; ip -n "$n" link set lo up; done
# El "cable" de wg0 es un bridge dentro de su propio namespace (sw): así ni
# br_netfilter ni las reglas FORWARD del host (p. ej. las de Docker) le afectan.
ip -n sw link add br-sim type bridge && ip -n sw link set br-sim up
ip -n sw link add s-br type veth peer name wg0 netns srv && ip -n sw link set s-br master br-sim up
for d in a1:10.252.1.2 a2:10.252.1.3 b1:10.252.2.2; do
    n=${d%%:*}; a=${d#*:}
    ip -n sw link add "$n-br" type veth peer name eth0 netns "$n"
    ip -n sw link set "$n-br" master br-sim up
    ip -n "$n" addr add "$a/32" dev eth0 && ip -n "$n" link set eth0 up
    ip -n "$n" route add 10.252.0.1 dev eth0 && ip -n "$n" route add default via 10.252.0.1 dev eth0
done
# Router del cliente 1 (r1, 10.252.1.5) con su LAN 192.168.88.0/24 detrás (lan1 = 192.168.88.10).
ip -n sw link add r1-br type veth peer name eth0 netns r1 && ip -n sw link set r1-br master br-sim up
ip -n r1 addr add 10.252.1.5/32 dev eth0 && ip -n r1 link set eth0 up
ip -n r1 route add 10.252.0.1 dev eth0 && ip -n r1 route add 10.252.0.0/16 via 10.252.0.1 dev eth0
ip -n r1 link add lan type veth peer name eth0 netns lan1
ip -n r1 addr add 192.168.88.1/24 dev lan && ip -n r1 link set lan up
ip -n lan1 addr add 192.168.88.10/24 dev eth0 && ip -n lan1 link set eth0 up && ip -n lan1 route add default via 192.168.88.1
ip netns exec r1 sysctl -qw net.ipv4.ip_forward=1
ip -n srv addr add 10.252.0.1/16 dev wg0 && ip -n srv link set wg0 up
# En WireGuard la ruta a la LAN va por wg0 (AllowedIPs del router); en la simulación, vía r1.
ip -n srv route add 192.168.88.0/24 via 10.252.1.5 dev wg0
ip link add eth0 netns srv type veth peer name eth0 netns inet
ip -n srv addr add 198.51.100.1/24 dev eth0 && ip -n srv link set eth0 up
ip -n inet addr add 198.51.100.2/24 dev eth0 && ip -n inet addr add 8.8.8.8/32 dev lo && ip -n inet link set eth0 up
ip -n srv route add default via 198.51.100.2
ip netns exec srv sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.wg0.send_redirects=0
ip netns exec srv iptables -P FORWARD DROP

printf '10.252.1.0/24 192.168.88.0/24\n10.252.2.0/24\n; iptables -F\n' >"$LIST"
printf '10.252.1.0/24\n' >"$DNS_LIST"          # sólo el cliente 1 tiene filtros DNS
ip netns exec srv iptables -P INPUT DROP          # el resolver sólo es accesible por la regla propia

# Servidores de prueba: «resolver» del panel en 10.252.0.1:53 y un DNS/DoT de Internet en 8.8.8.8.
udp_srv() { ip netns exec "$1" python3 -c "
import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('$2', 53))
while True:
    d, a = s.recvfrom(512); s.sendto(b'$3', a)" & PIDS+=($!); }
udp_srv srv 10.252.0.1 resolver
udp_srv inet 8.8.8.8 internet
ip netns exec inet python3 -c "
import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('8.8.8.8', 853)); s.listen()
while True: s.accept()[0].close()" & PIDS+=($!)
# Reenvío de puertos: servicios que responden con la IP de origen que ven.
tcp_srv() { ip netns exec "$1" python3 -c "
import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('0.0.0.0', $2)); s.listen()
while True:
    c, a = s.accept(); c.sendall(('$3 ' + a[0]).encode()); c.close()" & PIDS+=($!); }
udp_echo() { ip netns exec "$1" python3 -c "
import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('0.0.0.0', $2))
while True:
    d, a = s.recvfrom(512); s.sendto(('$3 ' + a[0]).encode(), a)" & PIDS+=($!); }
tcp_srv a1 80 web-a1
tcp_srv a1 22 ssh-a1
tcp_srv lan1 8000 nas-lan1
udp_echo b1 7777 udp-b1
printf '%s\n' "tcp 8080 10.252.1.2 80" "tcp 9090 192.168.88.10 8000" "udp 7000 10.252.2.2 7777" \
    "tcp 22 10.252.1.2 22" "tcp 99999 10.252.1.2 80" "tcp 8081 10.252.1.2; iptables -F" "icmp 1 10.252.1.2 1" >"$FWD_LIST"
sleep 1
ip netns exec srv /usr/local/sbin/wgp-firewall up wg0
ip netns exec srv /usr/local/sbin/wgp-firewall up wg0   # idempotente

fail=0
check() { # check <ns> <ip> <pass|block> <descripción>
    local got=block
    ip netns exec "$1" ping -c1 -W1 "$2" >/dev/null 2>&1 && got=pass
    if [[ "$got" == "$3" ]]; then echo "ok    $1 -> $2  ($4)"; else echo "FALLO $1 -> $2  ($4): $got"; fail=1; fi
}
dns_check() { # dns_check <ns> <destino> <respuesta esperada> <descripción>
    local got
    got=$(ip netns exec "$1" python3 -c "
import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(b'q', ('$2', 53))
try: print(s.recv(512).decode())
except Exception: print('sin-respuesta')")
    if [[ "$got" == "$3" ]]; then echo "ok    $1 DNS $2 -> $got  ($4)"; else echo "FALLO $1 DNS $2 -> $got  ($4, esperado $3)"; fail=1; fi
}
dot_check() { # dot_check <ns> <pass|block> <descripción>
    local got=block
    ip netns exec "$1" timeout 3 bash -c 'echo > /dev/tcp/8.8.8.8/853' 2>/dev/null && got=pass
    if [[ "$got" == "$2" ]]; then echo "ok    $1 -> 8.8.8.8:853  ($3)"; else echo "FALLO $1 -> 8.8.8.8:853  ($3): $got"; fail=1; fi
}

check a1 10.252.1.3 pass  "LAN del mismo cliente"
check a2 10.252.1.2 pass  "LAN del mismo cliente"
check a1 10.252.2.2 block "entre clientes"
check b1 10.252.1.2 block "entre clientes"
check a1 8.8.8.8    pass  "Internet por NAT"
check b1 8.8.8.8    pass  "Internet por NAT"
check inet 10.252.1.2 block "Internet -> cliente"
check a1 192.168.88.10 pass "site-to-site: dispositivo -> LAN del router de su cliente"
check lan1 10.252.1.2 pass  "site-to-site: LAN del router -> dispositivo de su cliente"
check b1 192.168.88.10 block "site-to-site: otro cliente -> LAN ajena"
check lan1 10.252.2.2 block "site-to-site: LAN -> dispositivo de otro cliente"

fwd_check() { # fwd_check <tcp|udp> <puerto> <respuesta esperada|cerrado> <descripción>
    local got
    got=$(ip netns exec inet python3 -c "
import socket, sys
kind = socket.SOCK_STREAM if '$1' == 'tcp' else socket.SOCK_DGRAM
s = socket.socket(socket.AF_INET, kind); s.settimeout(2)
try:
    s.connect(('198.51.100.1', $2))
    if kind == socket.SOCK_DGRAM: s.send(b'hola')
    print(s.recv(512).decode() or 'cerrado')
except Exception: print('cerrado')")
    if [[ "$got" == "$3" ]]; then echo "ok    inet -> :$2/$1 = $got  ($4)"; else echo "FALLO inet -> :$2/$1 = $got  ($4, esperado $3)"; fail=1; fi
}
fwd_check tcp 8080 "web-a1 10.252.0.1" "puerto TCP -> dispositivo (con SNAT al servidor)"
fwd_check tcp 9090 "nas-lan1 10.252.0.1" "puerto TCP -> equipo de la LAN de un router"
fwd_check udp 7000 "udp-b1 10.252.0.1" "puerto UDP -> dispositivo de otro cliente"
fwd_check tcp 22   cerrado "puerto reservado (SSH del servidor) nunca se reenvía"
fwd_check tcp 8081 cerrado "línea inválida ignorada"
fwd_check tcp 80   cerrado "puerto no publicado"
check inet 10.252.1.2 block "Internet -> cliente directo sigue bloqueado"

dns_check a1 8.8.8.8 resolver "cliente con filtros: su DNS se redirige al resolver"
dns_check a1 10.252.0.1 resolver "cliente con filtros: resolver directo"
dns_check b1 8.8.8.8 internet "cliente sin filtros: DNS sin tocar"
dns_check b1 10.252.0.1 resolver "cliente sin filtros puede usar el resolver"
dot_check a1 block "DNS-over-TLS bloqueado con filtros"
dot_check b1 pass  "DNS-over-TLS permitido sin filtros"

[[ $(ip netns exec srv iptables -S FORWARD | grep -c wg-manager) -eq 6 ]] || { echo "FALLO reglas duplicadas"; fail=1; }

printf '10.252.2.0/24\n' >"$LIST"
printf 'udp 7000 10.252.2.2 7777\n' >"$FWD_LIST"
ip netns exec srv /usr/local/sbin/wgp-firewall sync
check a1 10.252.1.3 block "cliente suspendido"
check b1 8.8.8.8    pass  "otro cliente sigue con Internet"
fwd_check tcp 8080 cerrado "puerto retirado"
fwd_check udp 7000 "udp-b1 10.252.0.1" "los demás puertos siguen"

ip netns exec srv /usr/local/sbin/wgp-firewall down wg0
[[ $(ip netns exec srv iptables-save | grep -c wg-manager) -eq 0 ]] || { echo "FALLO down no limpió"; fail=1; }

exit $fail

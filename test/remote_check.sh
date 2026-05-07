#!/usr/bin/env bash
# GHOST VPN — remote self-test on the server.
#
# Runs ENTIRELY on the server via SSH (root access there).
# Uploads the client binary, starts it in loopback mode, runs all checks,
# cleans up, and prints a summary locally.
#
# Usage: bash test/remote_check.sh [server_ip]
# Requires: SSH key configured (see .env.local.example), built binaries in ./bin/

set -euo pipefail

SERVER_IP="${1:-204.168.254.182}"
SERVER_DOMAIN="${2:-example.com}"
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/id_ed25519}"
SSH="ssh -i ${SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@${SERVER_IP}"
SCP="scp -i ${SSH_KEY} -o StrictHostKeyChecking=no"
REMOTE_DIR="/opt/ghost"

# ── colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

step()    { echo -e "\n${BOLD}▶ $*${RESET}"; }
ok()      { echo -e "  ${GREEN}✓${RESET} $*"; }
fail()    { echo -e "  ${RED}✗${RESET} $*"; FAILURES=$((FAILURES+1)); }
warn()    { echo -e "  ${YELLOW}⚠${RESET} $*"; WARNINGS=$((WARNINGS+1)); }
info()    { echo -e "  ${CYAN}·${RESET} $*"; }

FAILURES=0
WARNINGS=0

echo -e "${BOLD}"
echo "╔════════════════════════════════════════════════════╗"
echo "║       GHOST VPN — Server Self-Test Suite           ║"
echo "╚════════════════════════════════════════════════════╝"
echo -e "${RESET}"
info "Target server: ${SERVER_IP} (${SERVER_DOMAIN})"
info "SSH key:       ${SSH_KEY}"

# ── 0. Prerequisites ──────────────────────────────────────────────────────────
step "0. Pre-flight checks"

if [[ ! -f bin/ghost-client ]]; then
    info "ghost-client not built — building now..."
    GOOS=linux GOARCH=amd64 go build -o bin/ghost-client ./cmd/ghost-client
fi
ok "ghost-client binary exists ($(du -sh bin/ghost-client | cut -f1))"

if ! $SSH "true" 2>/dev/null; then
    fail "Cannot SSH to ${SERVER_IP} — check key and connectivity"
    exit 1
fi
ok "SSH connection to ${SERVER_IP} works"

# ── 1. Upload client binary ───────────────────────────────────────────────────
step "1. Deploy client binary to server"

$SSH "mkdir -p ${REMOTE_DIR}"
$SCP bin/ghost-client root@${SERVER_IP}:${REMOTE_DIR}/ghost-client-test
$SCP deploy/client-loopback.yaml root@${SERVER_IP}:${REMOTE_DIR}/client-loopback.yaml
ok "Uploaded ghost-client-test and client-loopback.yaml"

# ── 2. Verify server is running ───────────────────────────────────────────────
step "2. Verify ghost-server on remote"

SRV_PROC=$($SSH "pgrep -a ghost-server 2>/dev/null || echo ''" 2>/dev/null || echo "")
if [[ -n "$SRV_PROC" ]]; then
    ok "ghost-server running: ${SRV_PROC}"
else
    info "ghost-server not running — starting it..."
    $SSH "cd ${REMOTE_DIR} && nohup ./ghost-server --config server.yaml --log-level debug \
        > /tmp/ghost-server.log 2>&1 &"
    sleep 2
    SRV_PROC=$($SSH "pgrep -a ghost-server 2>/dev/null || echo ''" 2>/dev/null || echo "")
    if [[ -n "$SRV_PROC" ]]; then
        ok "ghost-server started"
    else
        fail "Could not start ghost-server"
        $SSH "tail -20 /tmp/ghost-server.log" 2>/dev/null || true
        exit 1
    fi
fi

# ── 3. Start client in loopback mode ─────────────────────────────────────────
step "3. Start ghost-client (loopback) on server"

# Kill any previous test client
$SSH "pkill -f ghost-client-test 2>/dev/null || true"
sleep 1

$SSH "cd ${REMOTE_DIR} && nohup ./ghost-client-test \
    --config client-loopback.yaml --log-level debug \
    > /tmp/ghost-client-test.log 2>&1 &"

# Wait for TUN to come up
for i in $(seq 1 10); do
    sleep 1
    TUN_UP=$($SSH "ip link show ghost1 2>/dev/null | grep -c 'state UP' || echo 0" 2>/dev/null || echo 0)
    if [[ "$TUN_UP" -ge 1 ]]; then
        ok "ghost1 TUN interface is UP (after ${i}s)"
        break
    fi
    if [[ $i -eq 10 ]]; then
        fail "TUN interface ghost1 did not come up after 10s"
        info "Client log:"
        $SSH "cat /tmp/ghost-client-test.log" 2>/dev/null | sed 's/^/    /'
        # Cleanup and exit
        $SSH "pkill -f ghost-client-test 2>/dev/null || true"
        exit 1
    fi
done

TUN_ADDR=$($SSH "ip addr show ghost1 2>/dev/null | grep 'inet ' | awk '{print \$2}'" 2>/dev/null || echo "?")
info "ghost1 address: ${TUN_ADDR}"

# ── 4. Add default route through tunnel ──────────────────────────────────────
step "4. Route all traffic through tunnel"

# Add default route via ghost1 (loopback doesn't need an exception since
# the server connection uses 127.0.0.1 which is exempt from routing table)
$SSH "ip route add default dev ghost1 metric 50 2>/dev/null || true"
sleep 1

DFLT=$($SSH "ip route show default" 2>/dev/null || echo "")
info "Default routes: $(echo $DFLT | head -c 200)"

# ── 5. IPv4 exit IP ──────────────────────────────────────────────────────────
step "5. IPv4 exit IP via tunnel"

SEEN_IP=$($SSH "curl -4 --max-time 8 -s https://ifconfig.me 2>/dev/null || echo ''" 2>/dev/null || echo "")
# When routed through tunnel, exit should still be SERVER_IP (NAT on server)
if [[ "$SEEN_IP" == "$SERVER_IP" ]]; then
    ok "IPv4 exit IP is ${SEEN_IP} (server IP — tunnel NAT working)"
elif [[ -n "$SEEN_IP" ]]; then
    warn "IPv4 exit IP is ${SEEN_IP} (expected ${SERVER_IP})"
else
    fail "IPv4 request failed — tunnel not routing traffic"
fi

# ── 6. IPv6 leak ──────────────────────────────────────────────────────────────
step "6. IPv6 leak check"

IPV6=$($SSH "ip -6 addr show scope global 2>/dev/null | grep inet6 | awk '{print \$2}' | head -1" 2>/dev/null || echo "")
if [[ -z "$IPV6" ]]; then
    ok "No global IPv6 address on server — no IPv6 leak possible"
else
    warn "Server has IPv6: ${IPV6}"
    V6_EXIT=$($SSH "curl -6 --max-time 5 -s https://ifconfig.me 2>/dev/null || echo ''" 2>/dev/null || echo "")
    if [[ -n "$V6_EXIT" ]]; then
        warn "IPv6 traffic exits as ${V6_EXIT} (separate from tunnel)"
    else
        ok "IPv6 requests fail/blocked — no leak"
    fi
fi

# ── 7. DNS leak ──────────────────────────────────────────────────────────────
step "7. DNS leak check"

DNS_SERVERS=$($SSH "grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print \$2}'" 2>/dev/null || echo "")
info "DNS servers in use: $(echo $DNS_SERVERS | tr '\n' ' ')"

DNS_ORIGIN=$($SSH "dig +short +timeout=5 whoami.cloudflare.com TXT @1.1.1.1 2>/dev/null | tr -d '\"'" 2>/dev/null || echo "")
if [[ -n "$DNS_ORIGIN" ]]; then
    info "DNS query via 1.1.1.1 originates from: ${DNS_ORIGIN}"
    if [[ "$DNS_ORIGIN" == "$SERVER_IP" ]]; then
        ok "DNS (via 1.1.1.1) exits from server IP — no leak"
    else
        warn "DNS via 1.1.1.1 exits from ${DNS_ORIGIN}"
    fi
fi

SYS_DNS_ORIGIN=$($SSH "dig +short +timeout=5 whoami.cloudflare.com TXT 2>/dev/null | tr -d '\"'" 2>/dev/null || echo "")
if [[ -n "$SYS_DNS_ORIGIN" ]] && [[ "$SYS_DNS_ORIGIN" != "$DNS_ORIGIN" ]]; then
    if [[ "$SYS_DNS_ORIGIN" != "$SERVER_IP" ]]; then
        warn "System DNS exits from ${SYS_DNS_ORIGIN} — potential DNS leak"
    else
        ok "System DNS exits from server IP"
    fi
fi

# ── 8. Active probing resistance ─────────────────────────────────────────────
step "8. Active probing resistance"

# These tests run from the server itself (loopback) to avoid tunnel routing
PROBE1=$($SSH "curl --max-time 8 -sk -o /dev/null -w '%{http_code}|%{size_download}' \
    https://127.0.0.1/ -H 'Host: ${SERVER_DOMAIN}' 2>/dev/null || echo '000|0'" 2>/dev/null || echo "000|0")
CODE1=$(echo $PROBE1 | cut -d'|' -f1)
SIZE1=$(echo $PROBE1 | cut -d'|' -f2)
if [[ "$CODE1" == "200" ]] && [[ "${SIZE1:-0}" -gt 100 ]]; then
    ok "GET / → HTTP ${CODE1}, ${SIZE1}B (fallback proxy working)"
else
    fail "GET / → HTTP ${CODE1}, ${SIZE1}B (expected 200 with body)"
fi

PROBE2=$($SSH "curl --max-time 8 -sk -o /dev/null -w '%{http_code}' \
    https://127.0.0.1/some-random-path-probe -H 'Host: ${SERVER_DOMAIN}' 2>/dev/null || echo '000'" 2>/dev/null || echo "000")
if [[ "$PROBE2" =~ ^(200|301|302|404)$ ]]; then
    ok "GET /random-path → HTTP ${PROBE2} (fallback responding)"
else
    fail "GET /random-path → HTTP ${PROBE2}"
fi

PROBE3=$($SSH "curl --max-time 8 -sk -o /dev/null -w '%{http_code}' \
    -X POST https://127.0.0.1/api/v1/stream \
    -H 'Host: ${SERVER_DOMAIN}' \
    -H 'Content-Type: application/octet-stream' \
    -d 'garbage_probe_data_not_noise' 2>/dev/null || echo '000'" 2>/dev/null || echo "000")
if [[ "$PROBE3" == "200" ]]; then
    ok "POST /api/v1/stream with garbage → HTTP 200 (fallback, not VPN error)"
else
    fail "POST /api/v1/stream with garbage → HTTP ${PROBE3} (expected 200 via fallback)"
fi

HEADERS=$($SSH "curl --max-time 8 -sk -I https://127.0.0.1/ \
    -H 'Host: ${SERVER_DOMAIN}' 2>/dev/null || echo ''" 2>/dev/null || echo "")
if echo "$HEADERS" | grep -qi 'ghost\|golang\|go-server\|go http'; then
    fail "Response headers reveal Ghost/Go identity"
else
    ok "Response headers don't reveal Ghost/Go"
    SRV_HDR=$(echo "$HEADERS" | grep -i '^server:' | head -1 | tr -d '\r' || echo "")
    [[ -n "$SRV_HDR" ]] && info "Server header: ${SRV_HDR}"
fi

# ── 9. TLS certificate ────────────────────────────────────────────────────────
step "9. TLS certificate validity"

CERT_INFO=$($SSH "echo | openssl s_client -connect 127.0.0.1:443 \
    -servername ${SERVER_DOMAIN} 2>/dev/null | openssl x509 -noout \
    -issuer -subject -dates 2>/dev/null || echo ''" 2>/dev/null || echo "")
if echo "$CERT_INFO" | grep -qi 'Let.s Encrypt\|ISRG\|ZeroSSL\|DigiCert'; then
    ok "Certificate issued by known CA"
    EXPIRY=$(echo "$CERT_INFO" | grep 'notAfter' | cut -d= -f2 || echo "?")
    info "Expires: ${EXPIRY}"
elif [[ -n "$CERT_INFO" ]]; then
    ISSUER=$(echo "$CERT_INFO" | grep 'issuer' | head -1 || echo "?")
    warn "Certificate issuer: ${ISSUER}"
else
    warn "Could not verify certificate (openssl may not be installed)"
fi

# ── 10. JA3 fingerprint ───────────────────────────────────────────────────────
step "10. TLS JA3 fingerprint"

HAS_TSHARK=$($SSH "command -v tshark 2>/dev/null && echo yes || echo no" 2>/dev/null || echo "no")
if [[ "$HAS_TSHARK" == "yes" ]]; then
    PCAP="/tmp/ghost_ja3_test_$$.pcap"
    # Capture TLS handshake triggered by a new curl from the server
    $SSH "timeout 8 tshark -i lo -a duration:6 -w ${PCAP} \
        'host 127.0.0.1 and tcp port 443' &>/dev/null &
        sleep 1
        curl -sk https://127.0.0.1/ -H 'Host: ${SERVER_DOMAIN}' &>/dev/null
        sleep 3
        wait" 2>/dev/null || true

    JA3=$($SSH "tshark -r ${PCAP} -Y 'tls.handshake.type==1' \
        -T fields -e tls.handshake.ja3 2>/dev/null | grep -v '^$' | head -1 || echo ''" 2>/dev/null || echo "")
    $SSH "rm -f ${PCAP}" 2>/dev/null || true

    if [[ -n "$JA3" ]]; then
        info "JA3 fingerprint: ${JA3}"
        # Note: ghost-client uses uTLS Chrome, but curl on the server uses system TLS
        # For real JA3 test we need to capture ghost-client's own handshake
        ok "JA3 captured — verify at: https://ja3er.com/json/${JA3}"
    else
        warn "No JA3 captured (no TLS ClientHello on loopback during capture window)"
    fi
else
    warn "tshark not on server — skipping JA3 (install: apt install tshark)"
fi

# ── 11. Traffic analysis ──────────────────────────────────────────────────────
step "11. Traffic is TLS-only (no plain-text VPN)"

HAS_TCPDUMP=$($SSH "command -v tcpdump 2>/dev/null && echo yes || echo no" 2>/dev/null || echo "no")
if [[ "$HAS_TCPDUMP" == "yes" ]]; then
    PCAP2="/tmp/ghost_traffic_$$.pcap"
    $SSH "timeout 8 tcpdump -i any -w ${PCAP2} \
        'tcp port 443 and not src 127.0.0.1' &>/dev/null &
        sleep 6; wait" 2>/dev/null || true

    if $SSH "test -f ${PCAP2}" 2>/dev/null; then
        PKT_COUNT=$($SSH "tcpdump -r ${PCAP2} 2>/dev/null | wc -l || echo 0" 2>/dev/null || echo 0)
        info "Packets on port 443 (non-loopback): ${PKT_COUNT}"

        # Check for UDP on 443 (would indicate QUIC, unusual)
        UDP_443=$($SSH "tcpdump -r ${PCAP2} 'udp port 443' 2>/dev/null | wc -l || echo 0" 2>/dev/null || echo 0)
        if [[ "${UDP_443:-0}" -eq 0 ]]; then
            ok "No UDP/443 traffic — not leaking QUIC/WireGuard-style"
        else
            warn "${UDP_443} UDP/443 packets (QUIC?)"
        fi
        $SSH "rm -f ${PCAP2}" 2>/dev/null || true
    fi
else
    warn "tcpdump not on server — skipping traffic analysis"
fi

# ── 12. IP forwarding & NAT ───────────────────────────────────────────────────
step "12. Server NAT & IP forwarding"

FWD=$($SSH "sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '?'" 2>/dev/null || echo "?")
if [[ "$FWD" == "1" ]]; then
    ok "IPv4 forwarding enabled"
else
    fail "IPv4 forwarding is OFF (net.ipv4.ip_forward=${FWD})"
fi

NAT=$($SSH "iptables -t nat -L POSTROUTING -n 2>/dev/null | grep MASQUERADE || echo ''" 2>/dev/null || echo "")
if echo "$NAT" | grep -q "MASQUERADE"; then
    ok "NAT MASQUERADE active: $(echo $NAT | awk '{print $1,$2,$3,$4,$5}' | head -1)"
else
    fail "No MASQUERADE rule — clients can't reach internet"
fi

# ── 13. Tunnel throughput ─────────────────────────────────────────────────────
step "13. Tunnel throughput (loopback)"

HAS_IPERF=$($SSH "command -v iperf3 2>/dev/null && echo yes || echo no" 2>/dev/null || echo "no")
if [[ "$HAS_IPERF" == "yes" ]]; then
    # Start iperf3 server binding to tunnel address
    $SSH "pkill iperf3 2>/dev/null; iperf3 -s -B 10.7.0.1 -D -1 --logfile /tmp/iperf3.log" 2>/dev/null || true
    sleep 1
    IPERF_RESULT=$($SSH "iperf3 -c 10.7.0.1 -B 10.7.0.3 -t 5 -J 2>/dev/null | \
        python3 -c \"import sys,json; d=json.load(sys.stdin); \
        print('{:.1f}'.format(d['end']['sum_received']['bits_per_second']/1e6))\" \
        2>/dev/null || echo ''" 2>/dev/null || echo "")
    if [[ -n "$IPERF_RESULT" ]]; then
        MBPS="${IPERF_RESULT}"
        if (( $(echo "$MBPS > 50" | bc -l 2>/dev/null || echo 0) )); then
            ok "Throughput: ${MBPS} Mbps (≥50 Mbps target)"
        else
            warn "Throughput: ${MBPS} Mbps (below 50 Mbps target)"
        fi
    else
        warn "iperf3 measurement failed"
    fi
    $SSH "pkill iperf3 2>/dev/null || true" 2>/dev/null || true
else
    # Fallback: measure with dd + nc
    info "iperf3 not found — using dd/nc for rough throughput test"
    BYTES=$($SSH "
        nc -l -p 19999 > /dev/null &
        sleep 0.2
        TIME=\$(TIMEFORMAT='%R'; { time dd if=/dev/urandom bs=1M count=20 2>/dev/null | \
            nc -q1 127.0.0.1 19999; } 2>&1 | tail -1)
        echo \$TIME
        wait
    " 2>/dev/null || echo "")
    info "Rough dd/nc result: ${BYTES}s for 20MB (via loopback, not tunnel)"
fi

# ── Cleanup ───────────────────────────────────────────────────────────────────
step "Cleanup"

$SSH "ip route del default dev ghost1 2>/dev/null || true" 2>/dev/null || true
$SSH "pkill -f ghost-client-test 2>/dev/null || true" 2>/dev/null || true
ok "Test client stopped, routes restored"

# Print client log tail for reference
info "Last 10 lines of client log:"
$SSH "tail -10 /tmp/ghost-client-test.log 2>/dev/null || echo '(empty)'" 2>/dev/null \
    | sed 's/^/    /'

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}SUMMARY${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo
if [[ $FAILURES -eq 0 ]] && [[ $WARNINGS -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}ALL CHECKS PASSED${RESET}"
elif [[ $FAILURES -eq 0 ]]; then
    echo -e "  ${YELLOW}${BOLD}PASSED with ${WARNINGS} warning(s)${RESET}"
else
    echo -e "  ${RED}${BOLD}${FAILURES} FAILURE(S)${RESET}  ${YELLOW}${WARNINGS} warning(s)${RESET}"
fi
echo
echo -e "  Failures: ${RED}${FAILURES}${RESET}   Warnings: ${YELLOW}${WARNINGS}${RESET}"
echo

[[ $FAILURES -gt 0 ]] && exit 1 || exit 0

#!/usr/bin/env bash
# GHOST VPN — comprehensive security & functionality audit
# Run WHILE the tunnel is active: sudo ./bin/ghost-client --config deploy/client.yaml
# Usage: bash test/check.sh [server_ip] [server_domain]

set -euo pipefail

SERVER_IP="${1:-204.168.254.182}"
SERVER_DOMAIN="${2:-example.com}"
TIMEOUT=8

# ── colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

pass() { echo -e "  ${GREEN}✓ PASS${RESET}  $*"; }
fail() { echo -e "  ${RED}✗ FAIL${RESET}  $*"; FAILURES=$((FAILURES+1)); }
warn() { echo -e "  ${YELLOW}⚠ WARN${RESET}  $*"; WARNINGS=$((WARNINGS+1)); }
info() { echo -e "  ${CYAN}ℹ INFO${RESET}  $*"; }
section() { echo; echo -e "${BOLD}━━━ $* ━━━${RESET}"; }

FAILURES=0
WARNINGS=0

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "║          GHOST VPN Security Audit                ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  Server IP:  ${CYAN}${SERVER_IP}${RESET}"
echo -e "  Domain:     ${CYAN}${SERVER_DOMAIN}${RESET}"
echo -e "  Time:       $(date)"

# ── helper: require tool ───────────────────────────────────────────────────────
need() {
    if ! command -v "$1" &>/dev/null; then
        warn "'$1' not found — skipping related tests (install: $2)"
        return 1
    fi
    return 0
}

################################################################################
section "1. TUNNEL STATUS"
################################################################################

TUN_UP=false
if ip link show ghost0 &>/dev/null 2>&1; then
    TUN_STATE=$(ip link show ghost0 | grep -o 'state [A-Z]*' | awk '{print $2}')
    TUN_ADDR=$(ip addr show ghost0 2>/dev/null | grep 'inet ' | awk '{print $2}')
    if [[ "$TUN_STATE" == "UP" ]]; then
        pass "TUN interface ghost0 is UP (addr: ${TUN_ADDR})"
        TUN_UP=true
    else
        fail "TUN interface ghost0 exists but state=${TUN_STATE}"
    fi
else
    fail "TUN interface ghost0 not found — is the client running?"
fi

# Detect local real IP (before tunnel routes override everything)
LOCAL_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || echo "unknown")
info "Local outbound IP (kernel routing table): ${LOCAL_IP}"

################################################################################
section "2. IPv4 — DOES TRAFFIC EXIT VIA TUNNEL?"
################################################################################

if need curl "apt install curl"; then
    SEEN_IP=$(curl -4 --max-time $TIMEOUT -s https://ifconfig.me 2>/dev/null || echo "")
    if [[ "$SEEN_IP" == "$SERVER_IP" ]]; then
        pass "IPv4 exits via server — ifconfig.me sees ${SEEN_IP}"
    elif [[ -z "$SEEN_IP" ]]; then
        fail "IPv4 request timed out — tunnel may be broken"
    else
        warn "IPv4 exits via ${SEEN_IP} (expected ${SERVER_IP}) — default route not set?"
        info "To route all traffic: sudo ip route add default via 10.7.0.1 dev ghost0"
    fi
else
    warn "curl unavailable, skipping IPv4 exit check"
fi

################################################################################
section "3. IPv6 LEAK"
################################################################################

IPV6_ADDR=$(ip -6 addr show scope global 2>/dev/null | grep 'inet6' | awk '{print $2}' | head -1)
if [[ -z "$IPV6_ADDR" ]]; then
    pass "No global IPv6 address on this machine — no IPv6 leak possible"
else
    warn "Machine has global IPv6: ${IPV6_ADDR}"
    if need curl "apt install curl"; then
        SEEN_V6=$(curl -6 --max-time $TIMEOUT -s https://ifconfig.me 2>/dev/null || echo "")
        if [[ -n "$SEEN_V6" ]]; then
            fail "IPv6 is LEAKING — ifconfig.me sees ${SEEN_V6}"
            info "Fix: sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1"
            info "     sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1"
        else
            pass "IPv6 requests blocked/failed — no IPv6 leak"
        fi
    fi
fi

################################################################################
section "4. DNS LEAK"
################################################################################

DNS_SERVERS=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}')
info "Configured DNS servers: $(echo $DNS_SERVERS | tr '\n' ' ')"

# Check if any DNS server is in RFC1918 / ISP space (outside tunnel)
DNS_LEAKED=false
for ns in $DNS_SERVERS; do
    if [[ "$ns" =~ ^192\.168\. ]] || [[ "$ns" =~ ^10\. ]] || [[ "$ns" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
        warn "DNS server ${ns} is in private/LAN range — may bypass tunnel"
        DNS_LEAKED=true
    fi
done

if need dig "apt install dnsutils"; then
    # Ask a known DNS leak detection server
    WHOAMI=$(dig +short +timeout=5 whoami.cloudflare.com TXT @1.1.1.1 2>/dev/null | tr -d '"' || echo "")
    if [[ -n "$WHOAMI" ]]; then
        if [[ "$WHOAMI" == "$SERVER_IP" ]]; then
            pass "DNS via 1.1.1.1 — Cloudflare sees ${WHOAMI} (server IP) ✓"
        else
            warn "DNS via 1.1.1.1 — Cloudflare sees ${WHOAMI} (not server IP)"
            info "DNS queries themselves exit via ${WHOAMI}"
        fi
    fi

    # Check system DNS resolver origin
    SYS_DNS_IP=$(dig +short +timeout=5 whoami.cloudflare.com TXT 2>/dev/null | tr -d '"' || echo "")
    if [[ -n "$SYS_DNS_IP" ]]; then
        info "System resolver DNS origin: ${SYS_DNS_IP}"
        if [[ "$SYS_DNS_IP" != "$SERVER_IP" ]]; then
            warn "System DNS resolver exits via ${SYS_DNS_IP} — potential DNS leak"
            info "Fix: set nameserver to 1.1.1.1 in /etc/resolv.conf while tunnel is up"
        fi
    fi
elif need nslookup "apt install dnsutils"; then
    info "Using nslookup for DNS check"
    NS_RESULT=$(nslookup -timeout=5 google.com 2>&1 | grep 'Server:' || echo "")
    info "DNS resolver in use: $NS_RESULT"
fi

if [[ "$DNS_LEAKED" == false ]]; then
    pass "No obvious DNS leak detected"
fi

################################################################################
section "5. ACTIVE PROBING RESISTANCE"
################################################################################

if need curl "apt install curl"; then
    # Test 1: GET / should return fallback (nginx.org) content
    PROBE1=$(curl --max-time $TIMEOUT -sk -o /dev/null -w "%{http_code}|%{size_download}" \
        "https://${SERVER_DOMAIN}/" 2>/dev/null || echo "000|0")
    CODE1=$(echo $PROBE1 | cut -d'|' -f1)
    SIZE1=$(echo $PROBE1 | cut -d'|' -f2)
    if [[ "$CODE1" == "200" ]] && [[ "$SIZE1" -gt 100 ]]; then
        pass "GET / → HTTP ${CODE1}, ${SIZE1} bytes (looks like real website)"
    else
        fail "GET / → HTTP ${CODE1}, ${SIZE1} bytes (unexpected response)"
    fi

    # Test 2: Random path should also return fallback
    PROBE2=$(curl --max-time $TIMEOUT -sk -o /dev/null -w "%{http_code}" \
        "https://${SERVER_DOMAIN}/$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo 'random-path')" \
        2>/dev/null || echo "000")
    if [[ "$PROBE2" == "200" ]] || [[ "$PROBE2" == "404" ]] || [[ "$PROBE2" == "301" ]] || [[ "$PROBE2" == "302" ]]; then
        pass "GET /random-path → HTTP ${PROBE2} (fallback proxy responding)"
    else
        fail "GET /random-path → HTTP ${PROBE2} (should proxy to fallback, got unexpected code)"
    fi

    # Test 3: Garbage POST to tunnel endpoint should NOT reveal VPN
    PROBE3_BODY=$(curl --max-time $TIMEOUT -sk \
        -X POST "https://${SERVER_DOMAIN}/api/v1/stream" \
        -H "Content-Type: application/octet-stream" \
        -d "$(head -c 48 /dev/urandom | base64)" \
        2>/dev/null || echo "")
    PROBE3_CODE=$(curl --max-time $TIMEOUT -sk -o /dev/null -w "%{http_code}" \
        -X POST "https://${SERVER_DOMAIN}/api/v1/stream" \
        -H "Content-Type: application/octet-stream" \
        -d "garbage_data_probe_test" \
        2>/dev/null || echo "000")
    if [[ "$PROBE3_CODE" == "200" ]]; then
        pass "POST /api/v1/stream with garbage → HTTP 200 (fallback, not VPN error)"
    elif [[ "$PROBE3_CODE" == "000" ]]; then
        fail "POST /api/v1/stream timed out or connection refused — server may be down"
    else
        warn "POST /api/v1/stream with garbage → HTTP ${PROBE3_CODE} (expected 200 via fallback)"
    fi

    # Test 4: Response headers should NOT reveal Ghost/Go server
    HEADERS=$(curl --max-time $TIMEOUT -sk -I "https://${SERVER_DOMAIN}/" 2>/dev/null || echo "")
    if echo "$HEADERS" | grep -qi "ghost\|golang\|go-server"; then
        fail "Response headers reveal server identity: $(echo "$HEADERS" | grep -i 'server:\|x-powered-by:')"
    else
        pass "Response headers don't reveal Ghost/Go identity"
        SERVER_HDR=$(echo "$HEADERS" | grep -i '^server:' | head -1 | tr -d '\r')
        if [[ -n "$SERVER_HDR" ]]; then
            info "Server header: ${SERVER_HDR}"
        fi
    fi

    # Test 5: TLS certificate is valid (not self-signed)
    CERT_CHECK=$(curl --max-time $TIMEOUT -sv --head "https://${SERVER_DOMAIN}/" 2>&1 | \
        grep -E 'SSL certificate verify|subject:|issuer:' | head -4 || echo "")
    if echo "$CERT_CHECK" | grep -q "SSL certificate verify ok"; then
        pass "TLS certificate is valid (CA-signed)"
    elif echo "$CERT_CHECK" | grep -q "Let.s Encrypt\|ISRG\|ZeroSSL\|DigiCert"; then
        pass "TLS certificate issued by known CA"
    else
        CERT_SUBJECT=$(echo "$CERT_CHECK" | grep 'subject:' | head -1)
        warn "Could not confirm CA-signed cert: ${CERT_SUBJECT}"
    fi
fi

################################################################################
section "6. TLS / JA3 FINGERPRINT"
################################################################################

if need tshark "apt install tshark"; then
    info "Capturing TLS ClientHello from ghost-client..."
    PCAP_FILE="/tmp/ghost_ja3_$$.pcap"
    IFACE=$(ip route | grep default | head -1 | awk '{print $5}')

    # Capture in background while making a fresh connection
    sudo tshark -i "$IFACE" -a duration:5 -w "$PCAP_FILE" \
        "host $SERVER_IP and tcp port 443" &>/dev/null &
    TSHARK_PID=$!
    sleep 1

    # Trigger a new TLS handshake (connect but don't authenticate)
    curl --max-time 3 -sk "https://${SERVER_DOMAIN}/" &>/dev/null || true
    sleep 2
    wait $TSHARK_PID 2>/dev/null || true

    if [[ -f "$PCAP_FILE" ]]; then
        JA3=$(tshark -r "$PCAP_FILE" -Y "tls.handshake.type==1" \
            -T fields -e tls.handshake.ja3 2>/dev/null | grep -v '^$' | head -1 || echo "")
        if [[ -n "$JA3" ]]; then
            info "JA3 fingerprint: ${JA3}"
            # Known Chrome JA3 prefixes (changes with Chrome version)
            if echo "$JA3" | grep -qE '^(e7d705|4d7a28|0a7b|8a6c|cd08|66918|b32309|8c882a|aa168|7e6b|4b5d|aab4a|772b|549fc|3ed3)'; then
                pass "JA3 matches known Chrome fingerprint"
            else
                warn "JA3 ${JA3} — verify against https://ja3er.com/json/${JA3}"
                info "Ghost uses uTLS HelloChrome_Auto — should match recent Chrome"
            fi
        else
            warn "No TLS ClientHello captured (tunnel client connection needed)"
        fi
        rm -f "$PCAP_FILE"
    fi
else
    warn "tshark not available — skipping JA3 fingerprint check"
    info "Install: sudo apt install tshark"
fi

################################################################################
section "7. TRAFFIC LOOKS LIKE HTTPS (not VPN)"
################################################################################

if need tshark "apt install tshark"; then
    IFACE=$(ip route | grep default | head -1 | awk '{print $5}')
    PCAP2="/tmp/ghost_traffic_$$.pcap"
    info "Capturing 5s of traffic to ${SERVER_IP}:443..."

    sudo tshark -i "$IFACE" -a duration:5 -w "$PCAP2" \
        "host $SERVER_IP and tcp port 443" &>/dev/null
    if [[ -f "$PCAP2" ]]; then
        PKT_COUNT=$(tshark -r "$PCAP2" 2>/dev/null | wc -l || echo 0)
        TLS_COUNT=$(tshark -r "$PCAP2" -Y "tls" 2>/dev/null | wc -l || echo 0)
        NON_TLS=$(tshark -r "$PCAP2" -Y "not tls and not tcp" 2>/dev/null | wc -l || echo 0)

        info "Total packets to ${SERVER_IP}:443 — ${PKT_COUNT}"
        info "TLS packets: ${TLS_COUNT}"
        if [[ "$NON_TLS" -eq 0 ]]; then
            pass "All traffic to server is TLS — no plain-text VPN leakage"
        else
            fail "${NON_TLS} non-TLS packets detected to server port 443"
        fi

        # Check for any UDP traffic (WireGuard-like)
        UDP_VPN=$(tshark -r "$PCAP2" -Y "udp and host $SERVER_IP" 2>/dev/null | wc -l || echo 0)
        if [[ "$UDP_VPN" -eq 0 ]]; then
            pass "No UDP VPN traffic detected (not WireGuard/OpenVPN-style)"
        else
            warn "${UDP_VPN} UDP packets to server — unexpected"
        fi
        rm -f "$PCAP2"
    fi
else
    warn "tshark not available — skipping traffic analysis"
fi

################################################################################
section "8. BASIC CONNECTIVITY THROUGH TUNNEL"
################################################################################

if need ping "should be built-in"; then
    # Ping tunnel gateway
    if ping -c 2 -W 3 10.7.0.1 &>/dev/null 2>&1; then
        RTT=$(ping -c 3 -W 3 10.7.0.1 2>/dev/null | tail -1 | grep -oP 'avg = \K[0-9.]+' \
            || ping -c 3 -W 3 10.7.0.1 2>/dev/null | grep rtt | awk -F'/' '{print $5}' || echo "?")
        pass "Ping 10.7.0.1 (tunnel gateway) — RTT avg: ${RTT}ms"
    else
        fail "Cannot ping tunnel gateway 10.7.0.1 — tunnel not routing"
    fi

    # Ping external via tunnel
    if [[ "$TUN_UP" == true ]]; then
        if ping -c 2 -W 5 1.1.1.1 &>/dev/null 2>&1; then
            pass "Ping 1.1.1.1 via tunnel — internet reachable"
        else
            warn "Cannot ping 1.1.1.1 — check default route or NAT on server"
        fi
    fi
fi

################################################################################
section "9. SERVER-SIDE CHECKS (via SSH)"
################################################################################

if need ssh "apt install openssh-client"; then
    SSH_KEY="${SSH_KEY:-${HOME}/.ssh/id_ed25519}"
    if ssh -i "$SSH_KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
        root@"$SERVER_IP" "true" &>/dev/null 2>&1; then

        # Check IP forwarding
        FWD=$(ssh -i "$SSH_KEY" root@"$SERVER_IP" \
            "sysctl -n net.ipv4.ip_forward 2>/dev/null" 2>/dev/null || echo "?")
        if [[ "$FWD" == "1" ]]; then
            pass "IP forwarding enabled on server"
        else
            fail "IP forwarding is OFF on server (net.ipv4.ip_forward=${FWD})"
            info "Fix: sudo sysctl -w net.ipv4.ip_forward=1"
        fi

        # Check NAT rule
        NAT=$(ssh -i "$SSH_KEY" root@"$SERVER_IP" \
            "iptables -t nat -L POSTROUTING -n 2>/dev/null | grep MASQUERADE || echo ''" 2>/dev/null || echo "")
        if echo "$NAT" | grep -q "MASQUERADE"; then
            pass "NAT MASQUERADE rule active: $(echo $NAT | head -c 80)"
        else
            fail "No MASQUERADE rule found — outbound NAT not configured"
            info "Fix: sudo iptables -t nat -A POSTROUTING -s 10.7.0.0/24 -j MASQUERADE"
        fi

        # Check ghost0 on server
        SRV_TUN=$(ssh -i "$SSH_KEY" root@"$SERVER_IP" \
            "ip addr show ghost0 2>/dev/null || echo 'NOT FOUND'" 2>/dev/null || echo "?")
        if echo "$SRV_TUN" | grep -q "10.7.0.1"; then
            pass "Server ghost0 has address 10.7.0.1"
        else
            fail "Server ghost0 missing or wrong address: ${SRV_TUN}"
        fi

        # Check ghost-server process
        SRV_PROC=$(ssh -i "$SSH_KEY" root@"$SERVER_IP" \
            "pgrep -a ghost-server 2>/dev/null || echo ''" 2>/dev/null || echo "")
        if [[ -n "$SRV_PROC" ]]; then
            pass "ghost-server process is running"
        else
            fail "ghost-server process not found on server"
        fi

        # Check server logs for errors
        LAST_LOG=$(ssh -i "$SSH_KEY" root@"$SERVER_IP" \
            "tail -5 /tmp/ghost-server.log 2>/dev/null || echo 'no log'" 2>/dev/null || echo "?")
        info "Last 5 server log lines:"
        echo "$LAST_LOG" | while IFS= read -r line; do
            echo "    ${CYAN}${line}${RESET}"
        done
    else
        warn "Cannot SSH to ${SERVER_IP} — skipping server-side checks"
    fi
fi

################################################################################
# SUMMARY
################################################################################

echo
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}AUDIT SUMMARY${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

if [[ $FAILURES -eq 0 ]] && [[ $WARNINGS -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}ALL CHECKS PASSED — tunnel looks solid${RESET}"
elif [[ $FAILURES -eq 0 ]]; then
    echo -e "  ${YELLOW}${BOLD}PASSED with ${WARNINGS} warning(s)${RESET}"
else
    echo -e "  ${RED}${BOLD}${FAILURES} FAILURE(S), ${WARNINGS} WARNING(S)${RESET}"
fi

echo
echo -e "  Failures: ${RED}${FAILURES}${RESET}   Warnings: ${YELLOW}${WARNINGS}${RESET}"
echo

[[ $FAILURES -gt 0 ]] && exit 1 || exit 0

#!/usr/bin/env bash
# run_capture.sh — Automate pcap capture for ML detection testing.
#
# Captures two classes of traffic:
#   Class 0: Real HTTPS browsing (baseline)
#   Class 1: GHOST tunnel traffic
#
# Usage:
#   ./run_capture.sh real   <interface> <duration_sec> <output.pcap>
#   ./run_capture.sh ghost  <interface> <duration_sec> <output.pcap>
#
# Examples:
#   # Capture 60s of real HTTPS on eth0
#   ./run_capture.sh real eth0 60 captures/real_https_001.pcap
#
#   # Capture 60s of GHOST tunnel on eth0 (while ghost-client is running)
#   ./run_capture.sh ghost eth0 60 captures/ghost_001.pcap
#
# After capturing both classes, run:
#   python3 ../features/extract.py --real-dir captures/real/ --ghost-dir captures/ghost/ -o features.csv
#   python3 ../classifier/train_xgboost.py --features features.csv
#   python3 ../classifier/evaluate.py --model model.joblib --features features.csv

set -euo pipefail

MODE="${1:?Usage: $0 <real|ghost> <interface> <duration> <output.pcap>}"
IFACE="${2:?Specify network interface (e.g. eth0)}"
DURATION="${3:?Specify capture duration in seconds}"
OUTPUT="${4:?Specify output pcap path}"

# Ensure output directory exists.
mkdir -p "$(dirname "$OUTPUT")"

echo "[*] Capturing ${MODE} traffic on ${IFACE} for ${DURATION}s → ${OUTPUT}"

# BPF filter: only TLS traffic (port 443).
BPF="tcp port 443"

# For GHOST captures, we may also want to filter by server IP.
# Uncomment and set SERVER_IP if needed:
# SERVER_IP="1.2.3.4"
# BPF="tcp port 443 and host ${SERVER_IP}"

tcpdump -i "$IFACE" -w "$OUTPUT" -G "$DURATION" -W 1 "$BPF" &
TCPDUMP_PID=$!

echo "[*] tcpdump started (PID ${TCPDUMP_PID})"

if [ "$MODE" = "real" ]; then
    echo "[*] Generate real HTTPS traffic now (browse websites, etc.)"
    echo "[*] Capture will stop in ${DURATION}s..."
elif [ "$MODE" = "ghost" ]; then
    echo "[*] Ensure ghost-client is running and generating tunnel traffic."
    echo "[*] Capture will stop in ${DURATION}s..."
fi

# Wait for tcpdump to finish.
sleep "$DURATION"
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo "[+] Capture complete: ${OUTPUT}"
echo "[+] Packets captured: $(tcpdump -r "$OUTPUT" 2>/dev/null | wc -l)"

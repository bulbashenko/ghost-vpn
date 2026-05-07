#!/usr/bin/env python3
"""
Flow-level feature extraction from pcap files for ML detection testing.

Extracts ~40 features per flow, inspired by CICFlowMeter:
- Packet size statistics (mean, std, min, max, percentiles) per direction
- Inter-arrival time (IAT) statistics per direction
- Flow duration, byte counts, packet counts
- Byte ratio (asymmetry)
- Burst features

Usage:
    python3 extract.py --real-dir captures/real/ --ghost-dir captures/ghost/ -o features.csv
    python3 extract.py --pcap single_file.pcap --label 0 -o features.csv

Requires: scapy, numpy, pandas
"""

import argparse
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scapy.all import rdpcap, TCP, IP


def extract_flows(pcap_path: str) -> dict:
    """Extract bidirectional flows from a pcap file.

    Returns dict mapping flow_key → list of (timestamp, size, direction) tuples.
    Direction: 0 = forward (client→server), 1 = backward (server→client).
    """
    packets = rdpcap(pcap_path)
    flows = {}

    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue

        ip = pkt[IP]
        tcp = pkt[TCP]

        # Canonical flow key (sorted IPs so both directions map to same flow).
        endpoints = sorted([
            (ip.src, tcp.sport),
            (ip.dst, tcp.dport),
        ])
        flow_key = (endpoints[0][0], endpoints[0][1],
                     endpoints[1][0], endpoints[1][1])

        # Direction: forward if src matches first endpoint.
        direction = 0 if (ip.src, tcp.sport) == endpoints[0] else 1

        ts = float(pkt.time)
        size = len(pkt)

        if flow_key not in flows:
            flows[flow_key] = []
        flows[flow_key].append((ts, size, direction))

    return flows


def compute_stats(values: list) -> dict:
    """Compute statistical features for a list of values."""
    if not values:
        return {
            "mean": 0, "std": 0, "min": 0, "max": 0,
            "p25": 0, "p50": 0, "p75": 0, "count": 0, "total": 0,
        }
    arr = np.array(values)
    return {
        "mean": float(np.mean(arr)),
        "std": float(np.std(arr)),
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "p25": float(np.percentile(arr, 25)),
        "p50": float(np.percentile(arr, 50)),
        "p75": float(np.percentile(arr, 75)),
        "count": len(values),
        "total": float(np.sum(arr)),
    }


def compute_iat(timestamps: list) -> list:
    """Compute inter-arrival times from sorted timestamps."""
    if len(timestamps) < 2:
        return []
    ts = sorted(timestamps)
    return [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]


def extract_features(flow_packets: list) -> dict:
    """Extract features from a single flow's packet list.

    flow_packets: list of (timestamp, size, direction) tuples.
    """
    if len(flow_packets) < 2:
        return None

    # Separate by direction.
    fwd = [(ts, sz) for ts, sz, d in flow_packets if d == 0]
    bwd = [(ts, sz) for ts, sz, d in flow_packets if d == 1]
    all_ts = [ts for ts, _, _ in flow_packets]
    all_sz = [sz for _, sz, _ in flow_packets]

    features = {}

    # Flow duration.
    features["duration"] = max(all_ts) - min(all_ts)

    # Total packet/byte counts.
    features["total_packets"] = len(flow_packets)
    features["total_bytes"] = sum(all_sz)
    features["fwd_packets"] = len(fwd)
    features["bwd_packets"] = len(bwd)
    features["fwd_bytes"] = sum(sz for _, sz in fwd)
    features["bwd_bytes"] = sum(sz for _, sz in bwd)

    # Byte ratio (asymmetry indicator).
    if features["fwd_bytes"] > 0:
        features["byte_ratio"] = features["bwd_bytes"] / features["fwd_bytes"]
    else:
        features["byte_ratio"] = 0

    # Packet size statistics — forward.
    fwd_sizes = [sz for _, sz in fwd]
    for k, v in compute_stats(fwd_sizes).items():
        features[f"fwd_pkt_size_{k}"] = v

    # Packet size statistics — backward.
    bwd_sizes = [sz for _, sz in bwd]
    for k, v in compute_stats(bwd_sizes).items():
        features[f"bwd_pkt_size_{k}"] = v

    # Packet size statistics — all.
    for k, v in compute_stats(all_sz).items():
        features[f"all_pkt_size_{k}"] = v

    # IAT — forward.
    fwd_iats = compute_iat([ts for ts, _ in fwd])
    for k, v in compute_stats(fwd_iats).items():
        features[f"fwd_iat_{k}"] = v

    # IAT — backward.
    bwd_iats = compute_iat([ts for ts, _ in bwd])
    for k, v in compute_stats(bwd_iats).items():
        features[f"bwd_iat_{k}"] = v

    # IAT — all.
    all_iats = compute_iat(all_ts)
    for k, v in compute_stats(all_iats).items():
        features[f"all_iat_{k}"] = v

    # Burst features (simple: count sequences of same-direction packets).
    bursts = []
    current_burst = 1
    for i in range(1, len(flow_packets)):
        if flow_packets[i][2] == flow_packets[i - 1][2]:
            current_burst += 1
        else:
            bursts.append(current_burst)
            current_burst = 1
    bursts.append(current_burst)
    for k, v in compute_stats(bursts).items():
        features[f"burst_{k}"] = v

    # Packets per second.
    if features["duration"] > 0:
        features["packets_per_sec"] = features["total_packets"] / features["duration"]
        features["bytes_per_sec"] = features["total_bytes"] / features["duration"]
    else:
        features["packets_per_sec"] = 0
        features["bytes_per_sec"] = 0

    return features


def process_pcap_dir(directory: str, label: int) -> list:
    """Process all pcap files in a directory."""
    records = []
    pcap_dir = Path(directory)
    if not pcap_dir.exists():
        print(f"[!] Directory not found: {directory}", file=sys.stderr)
        return records

    pcap_files = sorted(pcap_dir.glob("*.pcap")) + sorted(pcap_dir.glob("*.pcapng"))
    print(f"[*] Processing {len(pcap_files)} pcaps from {directory} (label={label})")

    for pcap_file in pcap_files:
        try:
            flows = extract_flows(str(pcap_file))
            for flow_key, packets in flows.items():
                feats = extract_features(packets)
                if feats is None:
                    continue
                feats["label"] = label
                feats["source_file"] = pcap_file.name
                feats["flow_key"] = str(flow_key)
                records.append(feats)
        except Exception as e:
            print(f"[!] Error processing {pcap_file}: {e}", file=sys.stderr)

    print(f"[+] Extracted {len(records)} flows from {directory}")
    return records


def main():
    parser = argparse.ArgumentParser(
        description="Extract flow features from pcap files for ML detection testing."
    )
    parser.add_argument("--real-dir", help="Directory with real HTTPS pcaps (label=0)")
    parser.add_argument("--ghost-dir", help="Directory with GHOST tunnel pcaps (label=1)")
    parser.add_argument("--pcap", help="Single pcap file to process")
    parser.add_argument("--label", type=int, default=0, help="Label for single pcap (default: 0)")
    parser.add_argument("-o", "--output", required=True, help="Output CSV path")
    parser.add_argument("--min-packets", type=int, default=5,
                        help="Minimum packets per flow to include (default: 5)")
    args = parser.parse_args()

    records = []

    if args.real_dir:
        records.extend(process_pcap_dir(args.real_dir, label=0))
    if args.ghost_dir:
        records.extend(process_pcap_dir(args.ghost_dir, label=1))
    if args.pcap:
        flows = extract_flows(args.pcap)
        for flow_key, packets in flows.items():
            feats = extract_features(packets)
            if feats is None:
                continue
            feats["label"] = args.label
            feats["source_file"] = os.path.basename(args.pcap)
            feats["flow_key"] = str(flow_key)
            records.append(feats)

    if not records:
        print("[!] No flows extracted. Check input paths.", file=sys.stderr)
        sys.exit(1)

    df = pd.DataFrame(records)

    # Filter by minimum packet count.
    before = len(df)
    df = df[df["total_packets"] >= args.min_packets]
    print(f"[*] Filtered {before - len(df)} flows with < {args.min_packets} packets")

    # Save.
    df.to_csv(args.output, index=False)
    print(f"[+] Saved {len(df)} flows ({df['label'].value_counts().to_dict()}) to {args.output}")
    print(f"[+] Features per flow: {len(df.columns) - 3}")  # minus label, source, flow_key


if __name__ == "__main__":
    main()

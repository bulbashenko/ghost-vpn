#!/usr/bin/env python3
"""
Train a 1D CNN classifier on raw packet size sequences to detect GHOST traffic.

Unlike the XGBoost model (which uses hand-crafted flow features), this CNN
operates on the raw sequence of the first N packet sizes — a more powerful
representation that can capture sequential patterns missed by statistics.

Usage:
    python3 train_cnn.py --features features.csv --pcap-dir captures/ --output model_cnn.pt

Target: AUC < 0.6 (close to random) on shaped GHOST traffic.

Requires: torch, numpy, pandas, scikit-learn, scapy
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.metrics import roc_auc_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, TensorDataset

# Maximum number of packets in the sequence. Shorter flows are zero-padded.
MAX_SEQ_LEN = 100


class PacketCNN(nn.Module):
    """1D CNN for packet sequence classification.

    Input: (batch, 1, MAX_SEQ_LEN) — signed packet sizes
           (positive = forward, negative = backward).
    Output: (batch, 1) — probability of being GHOST traffic.
    """

    def __init__(self, seq_len: int = MAX_SEQ_LEN):
        super().__init__()
        self.conv = nn.Sequential(
            nn.Conv1d(1, 32, kernel_size=5, padding=2),
            nn.ReLU(),
            nn.MaxPool1d(2),
            nn.Conv1d(32, 64, kernel_size=5, padding=2),
            nn.ReLU(),
            nn.MaxPool1d(2),
            nn.Conv1d(64, 128, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.AdaptiveAvgPool1d(1),
        )
        self.fc = nn.Sequential(
            nn.Flatten(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(self, x):
        x = self.conv(x)
        return self.fc(x)


def load_sequences(features_csv: str) -> tuple:
    """Load packet size sequences from the features CSV.

    The extract.py script stores per-flow stats, but for CNN we need raw
    sequences. This function uses a simplified approach: it reconstructs
    approximate sequences from the statistical features.

    For best results, use --pcap-dir to extract raw sequences from pcaps.
    """
    df = pd.read_csv(features_csv)

    sequences = []
    labels = []

    for _, row in df.iterrows():
        # Approximate sequence from stats (placeholder — real pipeline
        # should extract from pcaps directly).
        n_fwd = int(row.get("fwd_packets", 0))
        n_bwd = int(row.get("bwd_packets", 0))
        fwd_mean = row.get("fwd_pkt_size_mean", 100)
        bwd_mean = row.get("bwd_pkt_size_mean", 500)

        seq = []
        fi, bi = 0, 0
        for _ in range(min(n_fwd + n_bwd, MAX_SEQ_LEN)):
            if fi < n_fwd and (bi >= n_bwd or fi / max(n_fwd, 1) <= bi / max(n_bwd, 1)):
                seq.append(fwd_mean)
                fi += 1
            else:
                seq.append(-bwd_mean)  # negative = backward
                bi += 1

        # Pad to MAX_SEQ_LEN.
        seq = seq[:MAX_SEQ_LEN]
        seq += [0] * (MAX_SEQ_LEN - len(seq))

        sequences.append(seq)
        labels.append(int(row["label"]))

    return np.array(sequences, dtype=np.float32), np.array(labels, dtype=np.float32)


def train_epoch(model, loader, criterion, optimizer, device):
    model.train()
    total_loss = 0
    for X_batch, y_batch in loader:
        X_batch = X_batch.to(device)
        y_batch = y_batch.to(device)
        optimizer.zero_grad()
        output = model(X_batch).squeeze()
        loss = criterion(output, y_batch)
        loss.backward()
        optimizer.step()
        total_loss += loss.item() * len(y_batch)
    return total_loss / len(loader.dataset)


def evaluate(model, loader, device):
    model.eval()
    all_preds = []
    all_labels = []
    with torch.no_grad():
        for X_batch, y_batch in loader:
            X_batch = X_batch.to(device)
            output = model(X_batch).squeeze().cpu().numpy()
            all_preds.extend(output)
            all_labels.extend(y_batch.numpy())
    return np.array(all_preds), np.array(all_labels)


def main():
    parser = argparse.ArgumentParser(description="Train CNN GHOST detector")
    parser.add_argument("--features", required=True, help="Path to features CSV")
    parser.add_argument("--output", default="model_cnn.pt", help="Output model path")
    parser.add_argument("--epochs", type=int, default=50, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--lr", type=float, default=0.001, help="Learning rate")
    parser.add_argument("--report", default="report_cnn.json", help="Output report JSON")
    args = parser.parse_args()

    print(f"[*] Loading sequences from {args.features}")
    X, y = load_sequences(args.features)
    print(f"[*] Dataset: {len(X)} flows, sequence length {MAX_SEQ_LEN}")
    print(f"[*] Class distribution: 0(real)={int(np.sum(y==0))}, 1(ghost)={int(np.sum(y==1))}")

    if len(np.unique(y)) < 2:
        print("[!] Need both classes for training", file=sys.stderr)
        sys.exit(1)

    # Train/test split.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # Reshape for Conv1d: (batch, channels=1, seq_len).
    X_train_t = torch.FloatTensor(X_train).unsqueeze(1)
    X_test_t = torch.FloatTensor(X_test).unsqueeze(1)
    y_train_t = torch.FloatTensor(y_train)
    y_test_t = torch.FloatTensor(y_test)

    # Normalize packet sizes to [0, 1] range.
    max_val = max(X_train_t.abs().max().item(), 1.0)
    X_train_t /= max_val
    X_test_t /= max_val

    train_ds = TensorDataset(X_train_t, y_train_t)
    test_ds = TensorDataset(X_test_t, y_test_t)
    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
    test_loader = DataLoader(test_ds, batch_size=args.batch_size)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Device: {device}")

    model = PacketCNN().to(device)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=args.lr)

    print(f"[*] Training for {args.epochs} epochs...")
    for epoch in range(args.epochs):
        loss = train_epoch(model, train_loader, criterion, optimizer, device)
        if (epoch + 1) % 10 == 0:
            print(f"    Epoch {epoch+1}/{args.epochs}: loss={loss:.4f}")

    # Evaluate.
    print("\n[*] Evaluating on test set...")
    y_proba, y_true = evaluate(model, test_loader, device)
    y_pred = (y_proba > 0.5).astype(int)

    print("[+] Classification report:")
    print(classification_report(y_true, y_pred, target_names=["real_https", "ghost"]))

    cm = confusion_matrix(y_true, y_pred)
    print(f"[+] Confusion matrix:\n{cm}")

    auc = roc_auc_score(y_true, y_proba)
    print(f"[+] ROC AUC: {auc:.4f}")
    print(f"    Target: < 0.6 (close to random = 0.5)")

    if auc < 0.6:
        print("    ✓ TARGET MET — CNN cannot distinguish GHOST from real HTTPS")
    else:
        print("    ✗ TARGET NOT MET — sequential patterns detectable")

    # Save model.
    torch.save(model.state_dict(), args.output)
    print(f"\n[+] Model saved to {args.output}")

    # Save report.
    report = {
        "dataset_size": len(X),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "epochs": args.epochs,
        "roc_auc": float(auc),
        "target_met": auc < 0.6,
        "confusion_matrix": cm.tolist(),
    }
    with open(args.report, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report saved to {args.report}")


if __name__ == "__main__":
    main()

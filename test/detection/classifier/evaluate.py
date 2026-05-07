#!/usr/bin/env python3
"""
Evaluate a trained model against a features dataset and produce a
comprehensive detection report.

Usage:
    python3 evaluate.py --model model_xgboost.joblib --features features.csv
    python3 evaluate.py --model model_xgboost.joblib --features features.csv --output report.json

This script is used for iterative improvement: train shaper → capture traffic →
extract features → evaluate → identify top discriminating features → tune shaper.

Requires: scikit-learn, xgboost, pandas, numpy, joblib
"""

import argparse
import json
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


META_COLS = {"label", "source_file", "flow_key"}


def load_features(path: str) -> tuple:
    df = pd.read_csv(path)
    feature_cols = [c for c in df.columns if c not in META_COLS]
    X = df[feature_cols].fillna(0).values
    y = df["label"].values
    return X, y, feature_cols, df


def tpr_at_fpr_threshold(y_true, y_score, max_fpr=0.01):
    """Find the TPR at the largest FPR ≤ max_fpr."""
    fpr, tpr, thresholds = roc_curve(y_true, y_score)
    valid = fpr <= max_fpr
    if not np.any(valid):
        return 0.0, 0.5
    idx = np.where(valid)[0][-1]
    return float(tpr[idx]), float(thresholds[idx]) if idx < len(thresholds) else 0.5


def main():
    parser = argparse.ArgumentParser(description="Evaluate GHOST detection model")
    parser.add_argument("--model", required=True, help="Path to trained model (.joblib)")
    parser.add_argument("--features", required=True, help="Path to features CSV")
    parser.add_argument("--output", default="evaluation_report.json", help="Output report")
    parser.add_argument("--fpr-threshold", type=float, default=0.01,
                        help="Max FPR for TPR measurement (default: 0.01)")
    args = parser.parse_args()

    # Load model.
    print(f"[*] Loading model from {args.model}")
    bundle = joblib.load(args.model)
    clf = bundle["model"]
    scaler = bundle["scaler"]
    model_features = bundle["features"]

    # Load features.
    print(f"[*] Loading features from {args.features}")
    X, y, feature_cols, df = load_features(args.features)
    print(f"[*] Dataset: {len(X)} flows")
    print(f"[*] Class distribution: real={np.sum(y==0)}, ghost={np.sum(y==1)}")

    # Ensure feature alignment.
    if feature_cols != model_features:
        print("[!] Warning: feature columns differ from training", file=sys.stderr)
        # Try to align.
        df_features = df[[c for c in model_features if c in df.columns]].fillna(0)
        for c in model_features:
            if c not in df_features.columns:
                df_features[c] = 0
        X = df_features[model_features].values

    # Scale and predict.
    X_scaled = scaler.transform(X)
    y_pred = clf.predict(X_scaled)
    y_proba = clf.predict_proba(X_scaled)[:, 1]

    # Metrics.
    accuracy = accuracy_score(y, y_pred)
    precision = precision_score(y, y_pred, zero_division=0)
    recall = recall_score(y, y_pred, zero_division=0)  # TPR for ghost class
    f1 = f1_score(y, y_pred, zero_division=0)
    auc = roc_auc_score(y, y_proba)
    cm = confusion_matrix(y, y_pred)

    # TPR at controlled FPR.
    tpr_controlled, threshold = tpr_at_fpr_threshold(y, y_proba, args.fpr_threshold)

    print("\n" + "=" * 60)
    print("GHOST DETECTION EVALUATION REPORT")
    print("=" * 60)
    print(f"\nDataset: {len(X)} flows (real={np.sum(y==0)}, ghost={np.sum(y==1)})")
    print(f"\nClassification Report:")
    print(classification_report(y, y_pred, target_names=["real_https", "ghost"]))
    print(f"Confusion Matrix:")
    print(f"  TN={cm[0][0]:5d}  FP={cm[0][1]:5d}")
    print(f"  FN={cm[1][0]:5d}  TP={cm[1][1]:5d}")
    print(f"\nKey Metrics:")
    print(f"  Accuracy:           {accuracy:.4f}")
    print(f"  Precision (ghost):  {precision:.4f}")
    print(f"  Recall/TPR (ghost): {recall:.4f}")
    print(f"  F1 (ghost):         {f1:.4f}")
    print(f"  ROC AUC:            {auc:.4f}")
    print(f"\n  TPR at FPR≤{args.fpr_threshold:.0%}:    {tpr_controlled:.4f}")
    print(f"  Threshold:          {threshold:.4f}")

    # Verdict.
    print(f"\n{'=' * 60}")
    print("VERDICT:")
    targets_met = 0
    targets_total = 2

    if tpr_controlled < 0.05:
        print(f"  ✓ XGBoost TPR at FPR≤{args.fpr_threshold:.0%}: {tpr_controlled:.2%} < 5%")
        targets_met += 1
    else:
        print(f"  ✗ XGBoost TPR at FPR≤{args.fpr_threshold:.0%}: {tpr_controlled:.2%} >= 5%")

    if auc < 0.6:
        print(f"  ✓ ROC AUC: {auc:.4f} < 0.6 (near random)")
        targets_met += 1
    else:
        print(f"  ✗ ROC AUC: {auc:.4f} >= 0.6")

    print(f"\n  Targets met: {targets_met}/{targets_total}")
    if targets_met == targets_total:
        print("  → GHOST traffic is statistically indistinguishable from real HTTPS")
    else:
        print("  → Shaper needs improvement. Check feature importance for hints.")

    # Feature importance analysis.
    if hasattr(clf, "feature_importances_"):
        importances = clf.feature_importances_
        top_idx = np.argsort(importances)[::-1][:10]
        print(f"\nTop 10 discriminating features (tune shaper to reduce these):")
        for i, idx in enumerate(top_idx):
            name = model_features[idx]
            imp = importances[idx]

            # Show mean values per class for this feature.
            feat_vals = X[:, idx]
            mean_real = np.mean(feat_vals[y == 0])
            mean_ghost = np.mean(feat_vals[y == 1])
            print(f"  {i+1:2d}. {name:30s} imp={imp:.4f}  "
                  f"real={mean_real:.2f}  ghost={mean_ghost:.2f}")

    print("=" * 60)

    # Save report.
    report = {
        "dataset_size": len(X),
        "class_distribution": {"real": int(np.sum(y == 0)), "ghost": int(np.sum(y == 1))},
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall_tpr": float(recall),
        "f1": float(f1),
        "roc_auc": float(auc),
        "tpr_at_fpr_1pct": float(tpr_controlled),
        "threshold_at_fpr_1pct": float(threshold),
        "confusion_matrix": cm.tolist(),
        "targets": {
            "tpr_lt_5pct": tpr_controlled < 0.05,
            "auc_lt_0.6": auc < 0.6,
            "all_met": targets_met == targets_total,
        },
    }

    if hasattr(clf, "feature_importances_"):
        report["top_features"] = [
            {
                "name": model_features[idx],
                "importance": float(importances[idx]),
                "mean_real": float(np.mean(X[y == 0, idx])),
                "mean_ghost": float(np.mean(X[y == 1, idx])),
            }
            for idx in top_idx
        ]

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()

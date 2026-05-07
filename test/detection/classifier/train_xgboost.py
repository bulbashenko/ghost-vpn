#!/usr/bin/env python3
"""
Train an XGBoost classifier to detect GHOST tunnel traffic vs real HTTPS.

This is the baseline classifier for the ML detection harness. It uses
flow-level features extracted by features/extract.py.

Usage:
    python3 train_xgboost.py --features features.csv --output model.joblib

Target: TPR < 5% at FPR ≤ 1% on GHOST traffic (shaped).
If the classifier can't distinguish GHOST from real HTTPS, the shaper works.

Requires: xgboost, scikit-learn, pandas, numpy, joblib
"""

import argparse
import json
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    make_scorer,
    precision_recall_curve,
)
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier


# Features to exclude from training (metadata columns).
META_COLS = {"label", "source_file", "flow_key"}


def load_features(path: str) -> tuple:
    """Load feature CSV and split into X, y."""
    df = pd.read_csv(path)
    feature_cols = [c for c in df.columns if c not in META_COLS]
    X = df[feature_cols].fillna(0).values
    y = df["label"].values
    return X, y, feature_cols


def tpr_at_fpr(y_true, y_score, max_fpr=0.01):
    """Compute TPR at a given FPR threshold."""
    precision, recall, thresholds = precision_recall_curve(y_true, y_score)
    # Use ROC curve instead for FPR control.
    from sklearn.metrics import roc_curve
    fpr, tpr, _ = roc_curve(y_true, y_score)
    # Find TPR where FPR ≤ max_fpr.
    valid = fpr <= max_fpr
    if not np.any(valid):
        return 0.0
    return float(tpr[valid][-1])


def main():
    parser = argparse.ArgumentParser(description="Train XGBoost GHOST detector")
    parser.add_argument("--features", required=True, help="Path to features CSV")
    parser.add_argument("--output", default="model_xgboost.joblib", help="Output model path")
    parser.add_argument("--folds", type=int, default=5, help="Cross-validation folds")
    parser.add_argument("--report", default="report_xgboost.json", help="Output report JSON")
    args = parser.parse_args()

    print(f"[*] Loading features from {args.features}")
    X, y, feature_cols = load_features(args.features)
    print(f"[*] Dataset: {len(X)} flows, {len(feature_cols)} features")
    print(f"[*] Class distribution: 0(real)={np.sum(y==0)}, 1(ghost)={np.sum(y==1)}")

    if len(np.unique(y)) < 2:
        print("[!] Need both classes (0 and 1) for training", file=sys.stderr)
        sys.exit(1)

    # Scale features.
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # XGBoost classifier.
    clf = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        use_label_encoder=False,
        random_state=42,
    )

    # Cross-validation.
    print(f"[*] Running {args.folds}-fold cross-validation...")
    cv = StratifiedKFold(n_splits=args.folds, shuffle=True, random_state=42)

    scoring = {
        "accuracy": "accuracy",
        "precision": "precision",
        "recall": "recall",
        "f1": "f1",
        "roc_auc": "roc_auc",
    }

    cv_results = cross_validate(
        clf, X_scaled, y, cv=cv, scoring=scoring, return_train_score=False
    )

    print("\n[+] Cross-validation results:")
    for metric in scoring:
        scores = cv_results[f"test_{metric}"]
        print(f"    {metric}: {scores.mean():.4f} ± {scores.std():.4f}")

    # Train final model on all data.
    print("\n[*] Training final model on all data...")
    clf.fit(X_scaled, y)

    # Feature importance.
    importances = clf.feature_importances_
    top_k = 15
    top_idx = np.argsort(importances)[::-1][:top_k]
    print(f"\n[+] Top {top_k} discriminating features:")
    for i, idx in enumerate(top_idx):
        print(f"    {i+1}. {feature_cols[idx]}: {importances[idx]:.4f}")

    # Full classification report.
    y_pred = clf.predict(X_scaled)
    y_proba = clf.predict_proba(X_scaled)[:, 1]
    print("\n[+] Classification report (on training data):")
    print(classification_report(y, y_pred, target_names=["real_https", "ghost"]))

    cm = confusion_matrix(y, y_pred)
    print(f"[+] Confusion matrix:\n{cm}")

    auc = roc_auc_score(y, y_proba)
    print(f"[+] ROC AUC: {auc:.4f}")

    # TPR at FPR ≤ 1%.
    tpr_at_1pct = tpr_at_fpr(y, y_proba, max_fpr=0.01)
    print(f"[+] TPR at FPR≤1%: {tpr_at_1pct:.4f}")
    print(f"    Target: < 0.05 (5%)")

    if tpr_at_1pct < 0.05:
        print("    ✓ TARGET MET — GHOST traffic is statistically indistinguishable")
    else:
        print("    ✗ TARGET NOT MET — shaper needs improvement")
        print("    → Check top features above for shaper tuning hints")

    # Save model + scaler.
    joblib.dump({"model": clf, "scaler": scaler, "features": feature_cols}, args.output)
    print(f"\n[+] Model saved to {args.output}")

    # Save report.
    report = {
        "dataset_size": len(X),
        "n_features": len(feature_cols),
        "class_distribution": {"real": int(np.sum(y == 0)), "ghost": int(np.sum(y == 1))},
        "cv_results": {m: {"mean": float(cv_results[f"test_{m}"].mean()),
                           "std": float(cv_results[f"test_{m}"].std())}
                       for m in scoring},
        "roc_auc": float(auc),
        "tpr_at_fpr_1pct": float(tpr_at_1pct),
        "target_met": tpr_at_1pct < 0.05,
        "top_features": [
            {"name": feature_cols[idx], "importance": float(importances[idx])}
            for idx in top_idx
        ],
        "confusion_matrix": cm.tolist(),
    }
    with open(args.report, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report saved to {args.report}")


if __name__ == "__main__":
    main()

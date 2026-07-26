"""
End-to-end evaluation: detection accuracy, per-class classification metrics,
false-positive rate, and confusion matrix — written to docs/evaluation_report.md.
"""
import sqlite3
import pandas as pd
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
import os

DB_PATH = "db/anomaly_detection.db"
REPORT_PATH = "docs/evaluation_report.md"


def load_risk_scores():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("SELECT * FROM risk_scores;", conn)
    conn.close()
    return df


def evaluate():
    df = load_risk_scores()

    # --- Detection accuracy: alert-fired (risk_score >= 40) vs. is_attack ---
    df["alert_fired"] = (df["risk_score"] >= 40).astype(int)
    y_true = df["is_attack"]
    y_pred = df["alert_fired"]

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0

    # --- Classification: predicted_attack_type vs. true attack_type ---
    class_report = classification_report(
        df["attack_type"], df["rf_predicted_attack_type"], zero_division=0
    )

    # --- High-risk tier precision (stricter threshold) ---
    high_risk = df[df["risk_tier"] == "high"]
    high_risk_precision = (
        (high_risk["is_attack"] == 1).sum() / len(high_risk) if len(high_risk) > 0 else 0
    )

    report_lines = [
        "# Evaluation Report",
        "",
        "## Detection Accuracy (Alert Fired vs. Ground Truth, threshold=40)",
        f"- Precision: {precision:.4f}",
        f"- Recall: {recall:.4f}",
        f"- F1 Score: {f1:.4f}",
        "",
        "## Confusion Matrix (alert_fired vs. is_attack)",
        "",
        "|              | Predicted Normal | Predicted Attack |",
        "|--------------|-------------------|-------------------|",
        f"| Actual Normal | {tn} (TN) | {fp} (FP) |",
        f"| Actual Attack | {fn} (FN) | {tp} (TP) |",
        "",
        "## False Positive Rate",
        f"- FP Rate: {fp_rate:.4f} ({fp} false positives out of {fp+tn} true-negative cases)",
        f"- Contamination parameter used: 0.06 (matches known injection rate)",
        "",
        "## High-Risk Tier Precision (risk_score >= 70)",
        f"- Precision: {high_risk_precision:.4f} ({len(high_risk)} alerts in high tier)",
        "",
        "## Per-Class Classification Report (Random Forest attack-type prediction)",
        "```",
        class_report,
        "```",
        "",
        "## Notes",
        "- Metrics are computed against synthetic ground-truth labels (`is_attack`, `attack_type`) "
        "generated alongside the data, not external validation.",
        "- Accuracy alone is misleading on this imbalanced dataset (~6% attack rate); "
        "precision/recall/F1 and per-class metrics are reported instead.",
    ]

    os.makedirs("docs", exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    print(f"Precision: {precision:.4f} | Recall: {recall:.4f} | F1: {f1:.4f}")
    print(f"FP Rate: {fp_rate:.4f}")
    print(f"High-risk tier precision: {high_risk_precision:.4f}")
    print(f"Report written to {REPORT_PATH}")


if __name__ == "__main__":
    evaluate()
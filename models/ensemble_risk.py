"""
Combines iso_forest_scores + lof_scores + rf_predictions + cold-start rule
into a single weighted 0-100 risk score per event.
"""
import sqlite3
import pandas as pd
import numpy as np

DB_PATH = "db/anomaly_detection.db"

# Weights: three independent signals vote on the final risk score
W_ISO = 0.30
W_LOF = 0.25
W_RF = 0.35
W_COLD_START = 0.10

COLD_START_BONUS = 1.0  # full weight contribution if cold-start, else 0


def load_all():
    conn = sqlite3.connect(DB_PATH)
    features = pd.read_sql("SELECT log_id, user_id, device_id, resource, timestamp, "
                            "is_cold_start, attack_type, is_attack FROM features;", conn)
    iso = pd.read_sql("SELECT log_id, iso_forest_score FROM iso_forest_scores;", conn)
    lof = pd.read_sql("SELECT log_id, lof_score FROM lof_scores;", conn)
    rf = pd.read_sql("SELECT log_id, rf_predicted_attack_type, rf_confidence FROM rf_predictions;", conn)
    conn.close()

    df = features.merge(iso, on="log_id").merge(lof, on="log_id").merge(rf, on="log_id")
    return df


def compute_risk():
    df = load_all()

    # RF signal: confidence only counts toward risk if it predicted an actual attack type
    rf_risk_component = np.where(
        df["rf_predicted_attack_type"] != "none",
        df["rf_confidence"],
        0.0
    )

    cold_start_component = df["is_cold_start"].astype(float) * COLD_START_BONUS

    weighted = (
        W_ISO * df["iso_forest_score"] +
        W_LOF * df["lof_score"] +
        W_RF * rf_risk_component +
        W_COLD_START * cold_start_component
    )

    df["risk_score"] = (weighted * 100).round(2).clip(0, 100)

    def risk_tier(score):
        if score >= 70:
            return "high"
        elif score >= 40:
            return "medium"
        else:
            return "low"

    df["risk_tier"] = df["risk_score"].apply(risk_tier)

    conn = sqlite3.connect(DB_PATH)
    df[["log_id", "user_id", "device_id", "resource", "timestamp",
        "iso_forest_score", "lof_score", "rf_predicted_attack_type", "rf_confidence",
        "is_cold_start", "risk_score", "risk_tier",
        "attack_type", "is_attack"]].to_sql(
        "risk_scores", conn, if_exists="replace", index=False
    )
    conn.commit()
    conn.close()

    high_risk = df[df["risk_tier"] == "high"]
    true_attacks = df[df["is_attack"] == 1]
    overlap = df[(df["risk_tier"] == "high") & (df["is_attack"] == 1)]

    print(f"Total events: {len(df)}")
    print(f"High-risk (>=70): {len(high_risk)} ({len(high_risk)/len(df)*100:.2f}%)")
    print(f"Medium-risk (40-69): {len(df[df['risk_tier']=='medium'])}")
    print(f"Low-risk (<40): {len(df[df['risk_tier']=='low'])}")
    print(f"True attacks: {len(true_attacks)}")
    print(f"High-risk AND true attack: {len(overlap)}")
    print(f"Precision @ high-risk: {len(overlap)/len(high_risk)*100:.2f}%")
    print(f"Recall @ high-risk: {len(overlap)/len(true_attacks)*100:.2f}%")
    false_positives = len(high_risk) - len(overlap)
    print(f"False positive rate @ high-risk: {false_positives/len(high_risk)*100:.2f}%")


if __name__ == "__main__":
    compute_risk()
    
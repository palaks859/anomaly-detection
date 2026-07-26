"""
Explainability layer: for each event above the alert threshold, computes the
top-3 deviating features (z-score vs. population) and writes a plain-language
explanation into the alerts table.
"""
import sqlite3
import pandas as pd
import numpy as np
import uuid

DB_PATH = "db/anomaly_detection.db"

FEATURE_COLS = [
    "failed_logins_5min", "geo_distance_km", "device_known_baseline",
    "resource_access_rate_10min", "hour_sin", "hour_cos",
    "resource_outside_normal", "is_cold_start"
]

FEATURE_LABELS = {
    "failed_logins_5min": "Repeated failed logins in a short window",
    "geo_distance_km": "Login location far from usual location",
    "device_known_baseline": "Device not previously seen for this user",
    "resource_access_rate_10min": "Unusually high resource access rate",
    "hour_sin": "Login at an unusual hour",
    "hour_cos": "Login at an unusual hour",
    "resource_outside_normal": "Accessed a resource outside normal role",
    "is_cold_start": "User/device has limited history (elevated scrutiny)"
}

ALERT_THRESHOLD = 40  # medium and above become alerts


def load_data():
    conn = sqlite3.connect(DB_PATH)
    risk = pd.read_sql("SELECT * FROM risk_scores;", conn)
    non_dup_cols = [c for c in FEATURE_COLS if c != "is_cold_start"]

    features = pd.read_sql(
    "SELECT log_id, " + ", ".join(non_dup_cols) + " FROM features;",
    conn
)
    conn.close()

    return risk.merge(features, on="log_id")


def compute_top_reasons(df):
    """Z-score each feature across the population, rank per row, take top 3 by |z|.
    hour_sin/hour_cos are combined into one 'hour deviation' signal so they
    don't occupy two of the three reason slots for the same underlying cause.
    """
    z_scores = pd.DataFrame(index=df.index)

    # Calculate z-scores for all features except hour_sin/hour_cos
    for col in FEATURE_COLS:
        if col in ("hour_sin", "hour_cos"):
            continue

        mean = df[col].mean()
        std = df[col].std()
        std = std if std > 1e-6 else 1.0

        z_scores[col] = (df[col] - mean) / std

    # Combine hour_sin/hour_cos into one "hour deviation"
    hour_angle = np.arctan2(df["hour_sin"], df["hour_cos"])

    mean_sin = df["hour_sin"].mean()
    mean_cos = df["hour_cos"].mean()
    mean_angle = np.arctan2(mean_sin, mean_cos)

    angular_diff = np.abs(
        np.arctan2(
            np.sin(hour_angle - mean_angle),
            np.cos(hour_angle - mean_angle)
        )
    )

    std_diff = angular_diff.std()
    std_diff = std_diff if std_diff > 1e-6 else 1.0

    z_scores["hour_deviation"] = (
        angular_diff - angular_diff.mean()
    ) / std_diff

    label_map = dict(FEATURE_LABELS)
    label_map["hour_deviation"] = "Login at an unusual hour"

    top_reasons_list = []
    top_reasons_detail = []

    for _, row in z_scores.iterrows():

        abs_z = row.abs().sort_values(ascending=False)

        top3 = abs_z.head(3)

        reasons = [label_map[col] for col in top3.index]

        top_reasons_list.append("; ".join(reasons))

        detail = {
            col: round(float(row[col]), 2)
            for col in top3.index
        }

        top_reasons_detail.append(detail)

    return top_reasons_list, top_reasons_detail


def generate_alerts():
    df = load_data()
    alert_candidates = df[df["risk_score"] >= ALERT_THRESHOLD].copy()

    if alert_candidates.empty:
        print("No events above alert threshold.")
        return

    top_reasons, top_reasons_detail = compute_top_reasons(alert_candidates)
    alert_candidates["top_reasons"] = top_reasons
    alert_candidates["top_reasons_detail"] = [str(d) for d in top_reasons_detail]
    alert_candidates["alert_id"] = [str(uuid.uuid4()) for _ in range(len(alert_candidates))]
    alert_candidates["status"] = "open"

    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM alerts;")
    conn.commit()

    alert_candidates.rename(columns={
        "rf_predicted_attack_type": "predicted_attack_type",
        "rf_confidence": "classifier_confidence"
    }, inplace=True)

    out_cols = [
        "alert_id", "log_id", "timestamp", "user_id", "device_id", "resource",
        "iso_forest_score", "lof_score", "predicted_attack_type",
        "classifier_confidence", "risk_score", "top_reasons", "status"
    ]
    alert_candidates[out_cols].to_sql("alerts", conn, if_exists="append", index=False)

    # store detailed z-scores separately for the contribution chart (Step 16)
    alert_candidates[["alert_id", "top_reasons_detail"]].to_sql(
        "alert_reason_details", conn, if_exists="replace", index=False
    )

    conn.commit()
    conn.close()

    print(f"Generated {len(alert_candidates)} alerts (risk_score >= {ALERT_THRESHOLD})")
    print(alert_candidates[["user_id", "predicted_attack_type", "risk_score", "top_reasons"]].head(10))


if __name__ == "__main__":
    generate_alerts()
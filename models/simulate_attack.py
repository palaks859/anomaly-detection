"""
Live attack simulation: injects one fresh attack event for a random existing
user, then re-runs the feature engineering -> scoring -> explainability ->
MITRE -> narrative steps for JUST that new event, and returns the new alert_id.
Reuses generate_data.py's injectors so behavior matches training-time attacks.
"""
import sys
import sqlite3
import pandas as pd
import numpy as np
import random
import uuid
from datetime import datetime

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.generate_data import (
    ATTACK_INJECTORS, haversine_km, TRAVELER_CITY_POOL
)

DB_PATH = "db/anomaly_detection.db"

FEATURE_COLS = [
    "failed_logins_5min", "geo_distance_km", "device_known_baseline",
    "resource_access_rate_10min", "hour_sin", "hour_cos",
    "resource_outside_normal", "is_cold_start"
]


def pick_random_user():
    conn = sqlite3.connect(DB_PATH)
    users = pd.read_sql("""
        SELECT DISTINCT user_id, username, role, device_id, latitude, longitude, city
        FROM raw_logs WHERE is_attack = 0;
    """, conn)
    conn.close()
    row = users.sample(1).iloc[0]
    return {
        "user_id": row["user_id"], "username": row["username"], "role": row["role"],
        "known_devices": [row["device_id"]], "home_lat": row["latitude"],
        "home_lon": row["longitude"], "home_city": row["city"],
        "normal_resources": []  # filled below
    }


def get_normal_resources(user_id):
    conn = sqlite3.connect(DB_PATH)
    res = pd.read_sql(
        "SELECT DISTINCT resource FROM raw_logs WHERE user_id = ? AND is_attack = 0;",
        conn, params=(user_id,)
    )
    conn.close()
    return res["resource"].tolist() or ["Email_Server"]


def inject_and_score(attack_type=None):
    user = pick_random_user()
    user["normal_resources"] = get_normal_resources(user["user_id"])
    attack_type = attack_type or random.choice(list(ATTACK_INJECTORS.keys()))

    log_rows = []
    ATTACK_INJECTORS[attack_type](user, datetime.now(), log_rows)

    new_df = pd.DataFrame(log_rows)
    new_df["timestamp"] = pd.to_datetime(new_df["timestamp"])

    conn = sqlite3.connect(DB_PATH)
    new_df.to_sql("raw_logs", conn, if_exists="append", index=False)
    conn.commit()
    conn.close()

    print(f"Injected {len(new_df)} {attack_type} events for user {user['user_id']}")
    return new_df["log_id"].tolist(), user["user_id"], attack_type


def rescore_and_alert(log_ids, user_id):
    """Re-runs the full offline pipeline (acceptable for demo scale) so the
    new event gets fresh features, scores, and an alert row."""
    import subprocess
    scripts = [
        "features/build_features.py",
        "models/train_isolation_forest.py",
        "models/train_lof.py",
        "models/train_classifier.py",
        "models/ensemble_risk.py",
        "models/explain.py",
        "models/mitre_mapping.py",
        "models/incident_correlation.py",
        "models/llm_narrative.py"
    ]
    for script in scripts:
        subprocess.run([sys.executable, script], check=True)

    conn = sqlite3.connect(DB_PATH)
    new_alerts = pd.read_sql(
        "SELECT alert_id FROM alerts WHERE log_id IN ({}) ORDER BY risk_score DESC;".format(
            ",".join(f"'{lid}'" for lid in log_ids)
        ), conn
    )
    conn.close()
    return new_alerts["alert_id"].tolist()


def run_simulation(attack_type=None):
    log_ids, user_id, chosen_type = inject_and_score(attack_type)
    alert_ids = rescore_and_alert(log_ids, user_id)
    print(f"Simulation complete. New alert IDs: {alert_ids}")
    return alert_ids, chosen_type, user_id


if __name__ == "__main__":
    run_simulation()
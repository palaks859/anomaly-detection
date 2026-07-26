"""
Trains IsolationForest on behavioral features.
Writes anomaly scores back into a new 'iso_forest_scores' table.
"""
import sqlite3
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

DB_PATH = "db/anomaly_detection.db"
MODEL_DIR = "models"

FEATURE_COLS = [
    "failed_logins_5min", "geo_distance_km", "device_known_baseline",
    "resource_access_rate_10min", "hour_sin", "hour_cos",
    "resource_outside_normal", "is_cold_start"
]

CONTAMINATION = 0.06  # matches injection rate from generate_data.py
N_ESTIMATORS = 200
RANDOM_STATE = 42


def load_features():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("SELECT * FROM features;", conn)
    conn.close()
    return df


def train():
    df = load_features()
    X = df[FEATURE_COLS].values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=-1
    )
    model.fit(X_scaled)

    # decision_function: higher = more normal. Flip and rescale so higher = more anomalous, range ~0-1
    raw_scores = model.decision_function(X_scaled)
    predictions = model.predict(X_scaled)  # -1 = anomaly, 1 = normal

    anomaly_score = (raw_scores.max() - raw_scores) / (raw_scores.max() - raw_scores.min())

    df["iso_forest_score"] = anomaly_score
    df["iso_forest_flag"] = (predictions == -1).astype(int)

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, f"{MODEL_DIR}/isolation_forest.pkl")
    joblib.dump(scaler, f"{MODEL_DIR}/iso_scaler.pkl")

    conn = sqlite3.connect(DB_PATH)
    df[["log_id", "iso_forest_score", "iso_forest_flag"]].to_sql(
        "iso_forest_scores", conn, if_exists="replace", index=False
    )
    conn.commit()
    conn.close()

    flagged = df[df["iso_forest_flag"] == 1]
    true_attacks = df[df["is_attack"] == 1]
    overlap = df[(df["iso_forest_flag"] == 1) & (df["is_attack"] == 1)]

    print(f"Total events: {len(df)}")
    print(f"Flagged as anomalous: {len(flagged)} ({len(flagged)/len(df)*100:.2f}%)")
    print(f"True attacks in data: {len(true_attacks)}")
    print(f"Flagged AND true attack (overlap): {len(overlap)}")
    print(f"Recall on true attacks: {len(overlap)/len(true_attacks)*100:.2f}%")


if __name__ == "__main__":
    train()
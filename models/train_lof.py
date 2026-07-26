"""
Trains LocalOutlierFactor (distance-based) on the same feature set as IsolationForest.
Note: LOF in default mode (novelty=False) is fit-and-score only — it does not
support predicting on new unseen points separately. For this batch/offline
pipeline that's fine: we fit_predict once over the full feature set, same as
IsolationForest is used here. The scaler is still saved for reuse in explain.py.
"""
import sqlite3
import pandas as pd
import numpy as np
from sklearn.neighbors import LocalOutlierFactor
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

N_NEIGHBORS = 20
CONTAMINATION = 0.06


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

    lof = LocalOutlierFactor(
        n_neighbors=N_NEIGHBORS,
        contamination=CONTAMINATION,
        n_jobs=-1
    )
    predictions = lof.fit_predict(X_scaled)  # -1 = anomaly, 1 = normal
    neg_outlier_factor = lof.negative_outlier_factor_  # higher (closer to 0) = more normal

    # rescale so higher = more anomalous, range ~0-1
    raw = -neg_outlier_factor  # flip: higher = more anomalous
    lof_score = (raw - raw.min()) / (raw.max() - raw.min())

    df["lof_score"] = lof_score
    df["lof_flag"] = (predictions == -1).astype(int)

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(scaler, f"{MODEL_DIR}/lof_scaler.pkl")

    conn = sqlite3.connect(DB_PATH)
    df[["log_id", "lof_score", "lof_flag"]].to_sql(
        "lof_scores", conn, if_exists="replace", index=False
    )
    conn.commit()
    conn.close()

    flagged = df[df["lof_flag"] == 1]
    true_attacks = df[df["is_attack"] == 1]
    overlap = df[(df["lof_flag"] == 1) & (df["is_attack"] == 1)]

    print(f"Total events: {len(df)}")
    print(f"Flagged as anomalous: {len(flagged)} ({len(flagged)/len(df)*100:.2f}%)")
    print(f"True attacks in data: {len(true_attacks)}")
    print(f"Flagged AND true attack (overlap): {len(overlap)}")
    print(f"Recall on true attacks: {len(overlap)/len(true_attacks)*100:.2f}%")

    # quick agreement check with Isolation Forest
    conn = sqlite3.connect(DB_PATH)
    iso_df = pd.read_sql("SELECT log_id, iso_forest_flag FROM iso_forest_scores;", conn)
    conn.close()
    merged = df[["log_id", "lof_flag"]].merge(iso_df, on="log_id")
    agreement = (merged["lof_flag"] == merged["iso_forest_flag"]).mean()
    print(f"Agreement rate with Isolation Forest: {agreement*100:.2f}%")


if __name__ == "__main__":
    train()
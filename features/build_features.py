"""
Turns raw_logs into behavioral feature vectors, one row per log event.
Writes to the 'features' table in the SQLite DB.
"""
import sqlite3
import pandas as pd
import numpy as np
from math import radians, sin, cos, sqrt, atan2

DB_PATH = "db/anomaly_detection.db"


def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371
    lat1, lon1, lat2, lon2 = map(np.radians, [lat1, lon1, lat2, lon2])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    a = np.sin(dlat / 2)**2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon / 2)**2
    return R * 2 * np.arcsin(np.sqrt(a))


def load_raw_logs():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("SELECT * FROM raw_logs ORDER BY user_id, timestamp;", conn)
    conn.close()
    df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    format="mixed",
    errors="coerce"
)
    return df


def build_user_baselines(df):
    """Baseline computed from majority behavior, excludes injected attacks so
    the baseline represents 'normal', not contaminated by attacks."""
    normal = df[df["is_attack"] == 0]
    baselines = {}
    for user_id, grp in normal.groupby("user_id"):
        baselines[user_id] = {
            "home_lat": grp["latitude"].mode().iloc[0] if not grp.empty else 0.0,
            "home_lon": grp["longitude"].mode().iloc[0] if not grp.empty else 0.0,
            "known_devices": set(grp["device_id"].unique()),
            "normal_resources": set(grp["resource"].unique()),
            "typical_hours": grp["timestamp"].dt.hour.value_counts(),
            "history_count": len(grp)
        }
    return baselines


def failed_logins_last_5min(df):
    """Count failed logins for the same user in the preceding 5-minute window."""
    df = df.sort_values(["user_id", "timestamp"]).reset_index(drop=True)
    counts = np.zeros(len(df), dtype=int)

    for user_id, grp in df.groupby("user_id"):
        idx = grp.index.to_numpy()
        ts = grp["timestamp"].to_numpy()
        is_failed = (grp["status"] == "failed").to_numpy()
        left = 0
        for right in range(len(idx)):
            window_start = ts[right] - np.timedelta64(5, "m")
            while ts[left] < window_start:
                left += 1
            counts[idx[right]] = is_failed[left:right + 1].sum()

    return counts


def resource_access_rate(df, window_minutes=10):
    """Count of resource-access events by the same user in the preceding window."""
    df = df.sort_values(["user_id", "timestamp"]).reset_index(drop=True)
    counts = np.zeros(len(df), dtype=int)

    for user_id, grp in df.groupby("user_id"):
        idx = grp.index.to_numpy()
        ts = grp["timestamp"].to_numpy()
        left = 0
        for right in range(len(idx)):
            window_start = ts[right] - np.timedelta64(window_minutes, "m")
            while ts[left] < window_start:
                left += 1
            counts[idx[right]] = right - left + 1

    return counts


def build_features():
    df = load_raw_logs()
    baselines = build_user_baselines(df)

    # --- 1. failed logins in last 5 min ---
    df["failed_logins_5min"] = failed_logins_last_5min(df)

    # --- 2. distance from user's usual location ---
    def geo_dist(row):
        b = baselines.get(row["user_id"])
        if b is None:
            return 0.0
        return haversine_km(row["latitude"], row["longitude"], b["home_lat"], b["home_lon"])
    df["geo_distance_km"] = df.apply(geo_dist, axis=1)

    # --- 3. is this device known to this user? ---
    def device_known_baseline(row):
        b = baselines.get(row["user_id"])
        if b is None:
            return 0
        return int(row["device_id"] in b["known_devices"])
    df["device_known_baseline"] = df.apply(device_known_baseline, axis=1)

    # --- 4. resource access rate in session (10-min window) ---
    df["resource_access_rate_10min"] = resource_access_rate(df)

    # --- 5. hour-of-day, cyclical encoded ---
    df["hour"] = df["timestamp"].dt.hour
    df["hour_sin"] = np.sin(2 * np.pi * df["hour"] / 24)
    df["hour_cos"] = np.cos(2 * np.pi * df["hour"] / 24)

    # --- 6. is resource outside user's normal set? ---
    def resource_outside_normal(row):
        b = baselines.get(row["user_id"])
        if b is None:
            return 1
        return int(row["resource"] not in b["normal_resources"])
    df["resource_outside_normal"] = df.apply(resource_outside_normal, axis=1)

    # --- cold-start flag: fewer than N historical normal logins ---
    N_COLD_START = 5
    df["is_cold_start"] = df["user_id"].apply(
        lambda u: int(baselines.get(u, {}).get("history_count", 0) < N_COLD_START)
    )

    feature_cols = [
        "log_id", "timestamp", "user_id", "device_id", "resource",
        "failed_logins_5min", "geo_distance_km", "device_known_baseline",
        "resource_access_rate_10min", "hour_sin", "hour_cos",
        "resource_outside_normal", "is_cold_start",
        "attack_type", "is_attack"
    ]
    features_df = df[feature_cols].copy()

    conn = sqlite3.connect(DB_PATH)
    features_df.to_sql("features", conn, if_exists="replace", index=False)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_features_user ON features(user_id);")
    conn.commit()
    conn.close()

    print(f"Built {len(features_df)} feature rows")
    print(features_df[[
        "failed_logins_5min", "geo_distance_km", "device_known_baseline",
        "resource_access_rate_10min", "resource_outside_normal", "is_cold_start"
    ]].describe())

    return features_df


if __name__ == "__main__":
    build_features()
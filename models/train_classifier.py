"""
Trains RandomForestClassifier to predict attack_type (including 'none') per event.
Uses class_weight='balanced' and stratified train/test split for imbalance handling.
"""
import sqlite3
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os

DB_PATH = "db/anomaly_detection.db"
MODEL_DIR = "models"

FEATURE_COLS = [
    "failed_logins_5min", "geo_distance_km", "device_known_baseline",
    "resource_access_rate_10min", "hour_sin", "hour_cos",
    "resource_outside_normal", "is_cold_start"
]

N_ESTIMATORS = 300
MAX_DEPTH = 10
RANDOM_STATE = 42


def load_features():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("SELECT * FROM features;", conn)
    conn.close()
    return df


def train():
    df = load_features()
    X = df[FEATURE_COLS].values
    y_raw = df["attack_type"].values

    encoder = LabelEncoder()
    y = encoder.fit_transform(y_raw)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=MAX_DEPTH,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    y_pred = clf.test_pred = clf.predict(X_test)
    report = classification_report(
        y_test, y_pred, target_names=encoder.classes_, zero_division=0
    )
    cm = confusion_matrix(y_test, y_pred)

    print("Classification Report:")
    print(report)
    print("Confusion Matrix:")
    print(pd.DataFrame(cm, index=encoder.classes_, columns=encoder.classes_))

    # feature importances (used later in explainability layer)
    importances = pd.Series(clf.feature_importances_, index=FEATURE_COLS).sort_values(ascending=False)
    print("\nFeature Importances:")
    print(importances)

    # predict on full dataset for downstream ensemble scoring
    full_pred = clf.predict(X_scaled)
    full_proba = clf.predict_proba(X_scaled)
    confidence = full_proba.max(axis=1)
    predicted_labels = encoder.inverse_transform(full_pred)

    df["rf_predicted_attack_type"] = predicted_labels
    df["rf_confidence"] = confidence

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, f"{MODEL_DIR}/random_forest.pkl")
    joblib.dump(scaler, f"{MODEL_DIR}/rf_scaler.pkl")
    joblib.dump(encoder, f"{MODEL_DIR}/label_encoder.pkl")

    conn = sqlite3.connect(DB_PATH)
    df[["log_id", "rf_predicted_attack_type", "rf_confidence"]].to_sql(
        "rf_predictions", conn, if_exists="replace", index=False
    )
    conn.commit()
    conn.close()

    print(f"\nSaved model, scaler, encoder to {MODEL_DIR}/")
    print(f"Predictions written to rf_predictions table ({len(df)} rows)")


if __name__ == "__main__":
    train()
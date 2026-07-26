"""
Loads synthetic_access_logs.csv into SQLite.
Creates raw_logs (from CSV) and alerts (empty, populated later by explain.py).
"""
import sqlite3
import pandas as pd
import os

DB_PATH = "db/anomaly_detection.db"
CSV_PATH = "data/synthetic_access_logs.csv"

RAW_LOGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_logs (
    log_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    user_id TEXT NOT NULL,
    username TEXT,
    role TEXT,
    device_id TEXT,
    device_known INTEGER,
    resource TEXT,
    action TEXT,
    status TEXT,
    latitude REAL,
    longitude REAL,
    city TEXT,
    attack_type TEXT,
    is_attack INTEGER
);
"""

ALERTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    log_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT,
    resource TEXT,
    iso_forest_score REAL,
    lof_score REAL,
    predicted_attack_type TEXT,
    classifier_confidence REAL,
    risk_score REAL,
    top_reasons TEXT,
    mitre_technique TEXT,
    mitre_mitigation TEXT,
    llm_narrative TEXT,
    status TEXT DEFAULT 'open',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (log_id) REFERENCES raw_logs(log_id)
);
"""

INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_raw_logs_user ON raw_logs(user_id);",
    "CREATE INDEX IF NOT EXISTS idx_raw_logs_ts ON raw_logs(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts(user_id);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_risk ON alerts(risk_score);"
]


def setup_database():
    if not os.path.exists(CSV_PATH):
        raise FileNotFoundError(f"{CSV_PATH} not found. Run data/generate_data.py first.")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(RAW_LOGS_SCHEMA)
    cur.execute(ALERTS_SCHEMA)
    for idx in INDEXES:
        cur.execute(idx)
    conn.commit()

    df = pd.read_csv(CSV_PATH)
    df["device_known"] = df["device_known"].astype(int)

    cur.execute("DELETE FROM raw_logs;")
    conn.commit()

    df.to_sql("raw_logs", conn, if_exists="append", index=False)
    conn.commit()

    count = cur.execute("SELECT COUNT(*) FROM raw_logs;").fetchone()[0]
    print(f"Loaded {count} rows into raw_logs")

    conn.close()


if __name__ == "__main__":
    setup_database()
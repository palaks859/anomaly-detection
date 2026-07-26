"""
Groups a user's alerts into ordered incident chains when they occur within
a time-proximity window (default 2 hours) — e.g. brute-force -> credential
misuse -> lateral movement. Writes an 'incident_id' + 'chain_position' back
into the alerts table.
"""
import sqlite3
import pandas as pd
import uuid

DB_PATH = "db/anomaly_detection.db"
PROXIMITY_WINDOW_HOURS = 2


def load_alerts():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("SELECT * FROM alerts ORDER BY user_id, timestamp;", conn)
    conn.close()
    df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    format="mixed",
    errors="coerce"
)
    return df


def build_incident_chains():
    df = load_alerts()

    incident_ids = [None] * len(df)
    chain_positions = [None] * len(df)

    for user_id, grp in df.groupby("user_id"):
        idx = grp.index.tolist()
        current_incident = str(uuid.uuid4())
        position = 1
        incident_ids[idx[0]] = current_incident
        chain_positions[idx[0]] = position

        for i in range(1, len(idx)):
            prev_ts = grp["timestamp"].iloc[i - 1]
            curr_ts = grp["timestamp"].iloc[i]
            gap_hours = (curr_ts - prev_ts).total_seconds() / 3600

            if gap_hours <= PROXIMITY_WINDOW_HOURS:
                position += 1
            else:
                current_incident = str(uuid.uuid4())
                position = 1

            incident_ids[idx[i]] = current_incident
            chain_positions[idx[i]] = position

    df["incident_id"] = incident_ids
    df["chain_position"] = chain_positions

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    existing_cols = [row[1] for row in cur.execute("PRAGMA table_info(alerts);").fetchall()]

    if "incident_id" not in existing_cols:
        cur.execute("ALTER TABLE alerts ADD COLUMN incident_id TEXT;")

    if "chain_position" not in existing_cols:
        cur.execute("ALTER TABLE alerts ADD COLUMN chain_position INTEGER;")
    conn.commit()

    for _, row in df.iterrows():
        cur.execute(
            "UPDATE alerts SET incident_id = ?, chain_position = ? WHERE alert_id = ?",
            (row["incident_id"], row["chain_position"], row["alert_id"])
        )
    conn.commit()
    conn.close()

    multi_step = df.groupby("incident_id").filter(lambda g: len(g) > 1)
    print(f"Total alerts: {len(df)}")
    print(f"Incidents formed: {df['incident_id'].nunique()}")
    print(f"Multi-step incidents (chains of 2+): {multi_step['incident_id'].nunique()}")


if __name__ == "__main__":
    build_incident_chains()
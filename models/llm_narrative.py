import sqlite3
import pandas as pd
import ast
import time

DB_PATH = "db/anomaly_detection.db"
MAX_ALERTS = None  # set an int to cap rows during testing

SIGNAL_LABELS = {
    "failed_logins_5min": "repeated failed logins",
    "geo_distance_km": "a login location far from the norm",
    "device_known_baseline": "an unrecognized device",
    "resource_access_rate_10min": "an unusually high access rate",
    "hour_deviation": "an unusual login hour",
    "resource_outside_normal": "access to a resource outside the user's normal role",
    "is_cold_start": "limited account history"
}


def load_alerts_needing_narrative():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("""
        SELECT a.alert_id, a.user_id, a.resource, a.predicted_attack_type,
               a.risk_score, a.mitre_technique, a.llm_narrative, d.top_reasons_detail
        FROM alerts a
        LEFT JOIN alert_reason_details d ON a.alert_id = d.alert_id
        WHERE a.llm_narrative IS NULL;
    """, conn)
    conn.close()
    if MAX_ALERTS:
        df = df.head(MAX_ALERTS)
    return df


def generate_narrative(row):
    try:
        detail = ast.literal_eval(row["top_reasons_detail"]) if row["top_reasons_detail"] else {}
    except (ValueError, SyntaxError):
        detail = {}

    top_signal = max(detail.items(), key=lambda x: abs(x[1]))[0] if detail else None
    reason_phrase = SIGNAL_LABELS.get(top_signal, "anomalous behavior")

    return (
        f"User {row['user_id']}'s activity on {row['resource']} was flagged as "
        f"{row['predicted_attack_type'].replace('_', ' ')} (risk {row['risk_score']:.0f}/100), "
        f"driven primarily by {reason_phrase}."
    )


def run(batch_delay_sec=0.0):
    df = load_alerts_needing_narrative()
    if df.empty:
        print("No alerts need narratives.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    success, failed = 0, 0
    for _, row in df.iterrows():
        try:
            narrative = generate_narrative(row)
            cur.execute(
                "UPDATE alerts SET llm_narrative = ? WHERE alert_id = ?",
                (narrative, row["alert_id"])
            )
            success += 1
        except Exception as e:
            print(f"Failed for alert {row['alert_id']}: {e}")
            failed += 1
        if batch_delay_sec:
            time.sleep(batch_delay_sec)

    conn.commit()
    conn.close()
    print(f"Narratives generated: {success} | Failed: {failed}")


if __name__ == "__main__":
    run()
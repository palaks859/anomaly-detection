"""
Shared DB access helpers for the Streamlit dashboard.
"""
import sqlite3
import pandas as pd

DB_PATH = "db/anomaly_detection.db"


def get_connection():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def load_alerts():
    conn = get_connection()
    df = pd.read_sql("""
        SELECT alert_id, log_id, timestamp, user_id, device_id, resource,
       iso_forest_score, lof_score, predicted_attack_type,
       classifier_confidence, risk_score, top_reasons,
       mitre_technique, mitre_mitigation, llm_narrative, status
FROM alerts
        ORDER BY risk_score DESC;
    """, conn)
    conn.close()
    df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    format="mixed",
    errors="coerce"
)
    return df


def load_evaluation_metrics():
    """Parses key numbers out of docs/evaluation_report.md for KPI cards."""
    import re
    try:
        with open("docs/evaluation_report.md", "r", encoding="utf-8") as f:
            content = f.read()
        f1 = re.search(r"F1 Score:\s*([\d.]+)", content)
        fp_rate = re.search(r"FP Rate:\s*([\d.]+)", content)
        return {
            "f1_score": float(f1.group(1)) if f1 else None,
            "fp_rate": float(fp_rate.group(1)) if fp_rate else None
        }
    except FileNotFoundError:
        return {"f1_score": None, "fp_rate": None}

def load_incident_alerts(incident_id):
    """All alerts belonging to one incident, ordered by chain position."""
    conn = get_connection()
    df = pd.read_sql("""
        SELECT alert_id, log_id, timestamp, user_id, device_id, resource,
               predicted_attack_type, risk_score, chain_position,
               mitre_technique, mitre_mitigation
        FROM alerts
        WHERE incident_id = ?
        ORDER BY chain_position ASC;
    """, conn, params=(incident_id,))
    conn.close()
    df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    format="mixed",
    errors="coerce"
)
    return df


def get_incident_id_for_alert(alert_id):
    conn = get_connection()
    row = pd.read_sql(
        "SELECT incident_id FROM alerts WHERE alert_id = ?;",
        conn, params=(alert_id,)
    )
    conn.close()
    return row.iloc[0]["incident_id"] if not row.empty else None

def load_alert_reason_detail(alert_id):
    """Returns the top-3 feature z-score dict for one alert, or None."""
    import ast
    conn = get_connection()
    row = pd.read_sql(
        "SELECT top_reasons_detail FROM alert_reason_details WHERE alert_id = ?;",
        conn, params=(alert_id,)
    )
    conn.close()
    if row.empty:
        return None
    try:
        return ast.literal_eval(row.iloc[0]["top_reasons_detail"])
    except (ValueError, SyntaxError):
        return None
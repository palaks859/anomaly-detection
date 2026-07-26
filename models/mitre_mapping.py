"""
Static MITRE ATT&CK lookup — maps predicted attack_type to technique ID
and mitigation. Updates existing rows in the alerts table.
"""
import sqlite3
import pandas as pd

DB_PATH = "db/anomaly_detection.db"

MITRE_MAP = {
    "brute_force": {
        "technique": "T1110 — Brute Force",
        "mitigation": "Account lockout policy, enable MFA"
    },
    "credential_misuse": {
        "technique": "T1078 — Valid Accounts",
        "mitigation": "Least privilege, revoke excess permissions"
    },
    "lateral_movement": {
        "technique": "T1021 — Remote Services",
        "mitigation": "Network segmentation, restrict admin credential reuse"
    },
    "impossible_travel": {
        "technique": "T1078 — Valid Accounts",
        "mitigation": "Geo-velocity conditional access, forced re-auth"
    },
    "device_spoofing": {
        "technique": "T1078 — Valid Accounts",
        "mitigation": "Device attestation, MFA bound to registered devices"
    }
}


def apply_mitre_mapping():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    alerts = pd.read_sql(
        "SELECT alert_id, predicted_attack_type FROM alerts;",
        conn
    )

    updated = 0

    for _, row in alerts.iterrows():
        mapping = MITRE_MAP.get(row["predicted_attack_type"])

        if mapping is None:
            continue

        cur.execute(
            """
            UPDATE alerts
            SET mitre_technique = ?,
                mitre_mitigation = ?
            WHERE alert_id = ?
            """,
            (
                mapping["technique"],
                mapping["mitigation"],
                row["alert_id"]
            )
        )

        updated += 1

    conn.commit()
    conn.close()

    print(f"Updated {updated} alerts with MITRE ATT&CK mapping")


if __name__ == "__main__":
    apply_mitre_mapping()
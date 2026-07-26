import sqlite3
import pandas as pd

conn = sqlite3.connect("db/anomaly_detection.db")

df = pd.read_sql("""
SELECT alert_id, llm_narrative
FROM alerts
WHERE llm_narrative IS NOT NULL
LIMIT 5;
""", conn)

print(df)

conn.close()
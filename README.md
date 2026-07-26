# AI-Powered Behavioral Anomaly Detection for Cybersecurity

Honeywell Campus Connect — Round 2

## Setup

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run Order

1. python data/generate_data.py
2. python db/setup_db.py
3. python features/build_features.py
4. python models/train_isolation_forest.py
5. python models/train_classifier.py
6. python models/explain.py
7. streamlit run dashboard/app.py
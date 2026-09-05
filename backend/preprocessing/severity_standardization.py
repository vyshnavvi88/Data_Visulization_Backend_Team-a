import pandas as pd

df = pd.read_csv(
    "backend/data/processed/security_events_clean.csv"
)

severity_map = {
    "Critical":4,
    "High":3,
    "Medium":2,
    "Low":1
}

df["severity_score"] = df["severity"].map(severity_map)

df.to_csv(
    "backend/data/processed/security_events_standardized.csv",
    index=False
)
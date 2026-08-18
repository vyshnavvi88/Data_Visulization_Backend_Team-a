import pandas as pd

df = pd.read_csv("backend/data/processed/security_events_normalized.csv")

df = df.drop_duplicates()

df = df.dropna(subset=["event_id"])

df["timestamp"] = pd.to_datetime(df["timestamp"])

df["failed_login_attempts"] = df["failed_login_attempts"].fillna(0)

df["cvss_score"] = df["cvss_score"].fillna(0)

df.to_csv(
    "backend/data/processed/security_events_clean.csv",
    index=False
)
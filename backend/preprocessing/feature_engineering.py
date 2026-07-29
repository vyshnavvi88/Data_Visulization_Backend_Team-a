import pandas as pd

df = pd.read_csv(
    "backend/data/processed/security_events_mitre.csv"
)

df["risk_score"] = (
    df["severity_score"]*10
    +
    df["failed_login_attempts"]*2
    +
    df["cvss_score"]
)

df["is_high_risk"] = df["risk_score"] >= 35

df.to_csv(
    "backend/data/processed/final_security_dataset.csv",
    index=False
)
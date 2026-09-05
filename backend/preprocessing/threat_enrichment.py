

import pandas as pd

events = pd.read_csv(
    "backend/data/processed/security_events_standardized.csv"
)

threat = pd.read_csv(
    "backend/data/raw/threat_intelligence.csv"
)

events["threat_match"] = (
    events["source_ip"] ==
    threat.loc[0,"indicator_value"]
)

events.to_csv(
    "backend/data/processed/security_events_enriched.csv",
    index=False
)
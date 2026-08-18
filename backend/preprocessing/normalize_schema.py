import pandas as pd
import os

# Create processed folder if it doesn't exist
os.makedirs("backend/data/processed", exist_ok=True)

# Load Security Events Dataset
security_events = pd.read_csv(
    "backend/data/raw/security_events.csv"
)

print("=" * 60)
print("ORIGINAL COLUMN NAMES")
print("=" * 60)
print(security_events.columns.tolist())

# ---------------------------------------------------
# Rename columns (only if they exist)
# ---------------------------------------------------

column_mapping = {
    "Event ID": "event_id",
    "Timestamp": "timestamp",
    "Severity": "severity",
    "Source IP": "source_ip",
    "Destination IP": "destination_ip",
    "Event Type": "event_type",
    "Description": "description"
}

security_events.rename(columns=column_mapping, inplace=True)

print("\n")
print("=" * 60)
print("STANDARDIZED COLUMN NAMES")
print("=" * 60)
print(security_events.columns.tolist())

# Save processed file
security_events.to_csv(
    "backend/data/processed/security_events_normalized.csv",
    index=False
)

print("\nNormalized dataset saved successfully!")
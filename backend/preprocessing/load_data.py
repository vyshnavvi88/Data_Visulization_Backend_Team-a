import pandas as pd

# ===============================
# Load all datasets
# ===============================

assets = pd.read_csv("backend/data/raw/assets.csv")

incident_history = pd.read_csv(
    "backend/data/raw/incident_history.csv"
)

mitre_attack = pd.read_csv(
    "backend/data/raw/mitre_attack_mapping.csv"
)

security_events = pd.read_csv(
    "backend/data/raw/security_events.csv"
)

threat_intelligence = pd.read_csv(
    "backend/data/raw/threat_intelligence.csv"
)

vulnerabilities = pd.read_csv(
    "backend/data/raw/vulnerabilities.csv"
)

# ===============================
# Display Dataset Information
# ===============================

print("=" * 60)
print("SECURITY DATASETS LOADED SUCCESSFULLY")
print("=" * 60)

datasets = {
    "Assets": assets,
    "Incident History": incident_history,
    "MITRE Attack Mapping": mitre_attack,
    "Security Events": security_events,
    "Threat Intelligence": threat_intelligence,
    "Vulnerabilities": vulnerabilities,
}

for name, df in datasets.items():
    print(f"\n{name}")
    print(f"Rows    : {df.shape[0]}")
    print(f"Columns : {df.shape[1]}")
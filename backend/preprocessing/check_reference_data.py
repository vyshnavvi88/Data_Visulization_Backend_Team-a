import pandas as pd

print("Assets")
print(pd.read_csv("backend/data/raw/assets.csv").head())

print("\nThreat Intelligence")
print(pd.read_csv("backend/data/raw/threat_intelligence.csv").head())

print("\nVulnerabilities")
print(pd.read_csv("backend/data/raw/vulnerabilities.csv").head())

print("\nMITRE Mapping")
print(pd.read_csv("backend/data/raw/mitre_attack_mapping.csv").head())

print("\nIncident History")
print(pd.read_csv("backend/data/raw/incident_history.csv").head())
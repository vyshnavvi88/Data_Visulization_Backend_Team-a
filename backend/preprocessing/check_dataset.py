import pandas as pd

df = pd.read_csv("backend/data/raw/security_events.csv")

print("First 5 Rows:")
print(df.head())

print("\nColumn Data Types:")
print(df.dtypes)

print("\nSeverity Values:")
print(df["severity"].unique())

print("\nEvent Status Values:")
print(df["event_status"].unique())

print("\nMalware Detected Values:")
print(df["malware_detected"].unique())
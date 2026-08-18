from sklearn.preprocessing import StandardScaler
import pandas as pd

# Load Milestone 1 processed dataset
df = pd.read_csv(
    "backend/data/processed/final_security_dataset.csv"
)

print("Original shape:", df.shape)

# Check missing values
print("\nMissing values before preprocessing:")
print(df.isnull().sum())
# Step 3: Handle missing categorical values

categorical_columns = [
    "vulnerability_id",
    "mitre_id",
    "technique_name",
    "tactic"
]

for column in categorical_columns:
    df[column] = df[column].fillna("Unknown")

print("\nMissing values after handling:")
print(df.isnull().sum())
# Step 4: Encode categorical features

categorical_columns = [
    "event_type",
    "protocol",
    "source_country",
    "destination_country",
    "os",
    "event_status",
    "severity",
    "malware_detected",
    "department",
    "vulnerability_id",
    "threat_match",
    "technique_name",
    "tactic"
]

df = pd.get_dummies(
    df,
    columns=categorical_columns,
    dtype=int
)

print("\nData after encoding:")
print(df.dtypes)

print("\nNew shape:", df.shape)
# Step 5: Scale numerical ML features

numerical_features = [
    "failed_login_attempts",
    "cvss_score",
    "severity_score"
]

scaler = StandardScaler()

df[numerical_features] = scaler.fit_transform(
    df[numerical_features]
)

print("\nScaled numerical features:")
print(df[numerical_features].head())
# Step 6: Feature Selection

ml_features = [
    "failed_login_attempts",
    "cvss_score",
    "severity_score",

    "event_type_Brute Force",
    "event_type_Failed Login",
    "event_type_File Access",
    "event_type_Login Success",
    "event_type_Malware Detection",
    "event_type_Phishing Email",
    "event_type_Port Scan",
    "event_type_Privilege Escalation",
    "event_type_SQL Injection Attempt",
    "event_type_USB Device Connected",

    "protocol_HTTP",
    "protocol_HTTPS",
    "protocol_SMB",
    "protocol_SSH",
    "protocol_TCP",

    "source_country_India",
    "destination_country_India",

    "os_Linux",
    "os_Windows 10",
    "os_Windows 11",

    "event_status_Blocked",
    "event_status_Detected",
    "event_status_Failed",
    "event_status_Success",

    "severity_Critical",
    "severity_High",
    "severity_Low",
    "severity_Medium",

    "malware_detected_No",
    "malware_detected_Yes",

    "department_Finance",
    "department_HR",
    "department_IT",
    "department_Sales",

    "vulnerability_id_CVE-2023-1234",
    "vulnerability_id_CVE-2024-1045",
    "vulnerability_id_CVE-2024-2201",
    "vulnerability_id_Unknown",

    "threat_match_False",

    "technique_name_Brute Force",
    "technique_name_Unknown",

    "tactic_Credential Access",
    "tactic_Unknown"
]

X = df[ml_features]

print("\nSelected ML features:")
print(X.columns.tolist())

print("\nML feature matrix shape:")
print(X.shape)
# Step 7: Save ML-ready feature dataset

X.to_csv(
    "backend/data/processed/ml_features.csv",
    index=False
)

print("\nML feature dataset saved successfully.")
# Milestone 2 - Task 1: Feature Selection

## Objective

Identify the relevant features from the Milestone 1 processed security dataset
that will be used by the Milestone 2 machine learning anomaly detection engine.

## Selected Features

| Feature | Why Selected | Data Type | Importance |
|---|---|---|---|
| failed_login_attempts | Helps identify repeated failed authentication attempts and brute-force behavior. | Numeric | High |
| cvss_score | Represents the severity of a known vulnerability. | Numeric | High |
| severity_score | Provides a numerical representation of security-event severity. | Numeric | High |
| malware_detected | Indicates whether malware was detected during the event. | Categorical/Binary | High |
| event_type | Identifies the type of security event and attack behavior. | Categorical | High |
| event_status | Provides information about whether an event was successful, failed, blocked, or detected. | Categorical | Medium |
| protocol | Helps represent network communication behavior. | Categorical | Medium |
| severity | Represents the security severity category of the event. | Categorical | Medium |
| source_country | Can help identify unusual source locations. | Categorical | Medium |
| destination_country | Can help identify unusual destination locations. | Categorical | Medium |
| tactic | Provides MITRE ATT&CK attack-tactic context. | Categorical | High |
| technique_name | Provides MITRE ATT&CK technique information about the observed behavior. | Categorical | High |
| os | Provides operating-system context for the security event. | Categorical | Low |
| department | Helps represent normal activity patterns across departments. | Categorical | Low |

## Features Not Used as ML Inputs

The following fields are retained for identification, investigation, or reference
but are not selected as primary ML features:

- event_id
- source_ip
- destination_ip
- username
- device_name
- vulnerability_id
- asset_name
- mitre_id

## Target / Reference Field

`is_high_risk` is not used as an input feature for the anomaly detection model.

It was generated in Milestone 1 using the calculated `risk_score` and can be retained
as a reference label for evaluation if the labels are considered reliable.

## Risk Score

`risk_score` is also not selected as a primary input feature for the anomaly
detection model because it is already calculated from:

- severity_score
- failed_login_attempts
- cvss_score

It can instead be used later as part of the hybrid threat scoring or confidence
scoring layer.

## Model

The primary Milestone 2 anomaly detection model is Isolation Forest.

The selected features will be passed through the ML preprocessing pipeline before
model training.
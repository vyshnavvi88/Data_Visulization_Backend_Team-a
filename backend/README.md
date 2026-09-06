# 🛡️ AI Security Threat Detection — Backend

**Milestone 3 | Team A | Backend**

A Flask-based backend for real-time security threat detection using Machine Learning (Isolation Forest).
Connects to MongoDB (`Security_db`) and exposes REST APIs for the frontend dashboard.
Covers all 3 milestones: **Data Pipeline → ML Detection → Risk Intelligence**.

---

## 📁 Project Structure

```
backend/
├── app.py                          # Flask application entry point
├── db.py                           # MongoDB connection & helpers
├── config.py                       # Central config (MODEL_VERSION etc.)
├── requirements.txt                # Python dependencies
├── feature_selection.md            # M2 Task 1 — Feature documentation
├── upload_to_mongo.py              # Utility: upload CSV to MongoDB
│
├── routes/
│   ├── auth.py                     # POST /api/login, POST /api/signup
│   ├── events.py                   # GET  /api/events
│   ├── stats.py                    # GET  /api/stats
│   ├── threats.py                  # GET  /api/threats
│   ├── prediction_routes.py        # M2 — ML prediction APIs
│   ├── risk_routes.py              # M3 — Risk score APIs
│   └── incident_routes.py          # M3 — Incident & attack chain APIs
│
├── risk/                           # M3 — Risk intelligence engine
│   ├── risk_score.py               # Task 6 — Weighted risk scoring
│   ├── prioritization.py           # Task 7 — Incident prioritization
│   ├── correlation.py              # Task 8 — Event correlation
│   ├── recommendations.py          # Task 9 — Response recommendations
│   └── incident_builder.py         # Task 10 — Incident creation + MongoDB upload
│
├── services/
│   └── risk_context_engine.py      # Risk context orchestration
│
├── ml/
│   ├── anomaly_detection.py        # IF_v1 training script
│   ├── retrain_pipeline.py         # IF_v2 full retrain pipeline
│   ├── Store_predictions.py        # Store predictions to MongoDB
│   ├── model_evaluation.py         # Model statistics
│   └── test.py                     # Dataset diagnostics
│
├── models/
│   ├── isolation_forest.pkl        # Trained IF_v2 model
│   └── feature_columns.json        # 46 ML feature column names
│
├── data/
│   ├── processed/
│   │   ├── Security_db.processed_events.csv      # 1800 security events
│   │   ├── ml_features.csv                       # 46 ML features
│   │   ├── prediction_results.csv                # ML predictions
│   │   ├── m3_input_events.csv                   # M3 Task 1 input
│   │   ├── m3_events_with_criticality.csv        # M3 Task 2
│   │   ├── m3_events_with_vulnerability.csv      # M3 Task 3
│   │   ├── m3_events_with_mitre.csv              # M3 Task 4
│   │   ├── m3_events_with_ioc.csv                # M3 Task 5
│   │   ├── risk_scored_data.csv                  # M3 Task 6
│   │   ├── risk_classified_data.csv              # M3 Task 7
│   │   ├── correlated_events.csv                 # M3 Task 8
│   │   └── incidents.csv                         # M3 Task 10 — 718 incidents
│   └── raw/
│       ├── security_events.csv
│       ├── assets.csv
│       ├── vulnerabilities.csv
│       ├── threat_intelligence.csv
│       ├── incident_history.csv
│       └── mitre_attack_mapping.csv
│
├── preprocessing/                  # M1 data pipeline scripts
│   ├── ml_preprocessing.py
│   ├── data_cleaning.py
│   ├── feature_engineering.py
│   ├── mitre_mapping.py
│   ├── threat_enrichment.py
│   └── ...
│
└── tests/
    └── test_unit_plan.py           # 41 unit tests — all milestones (mentor's test plan)
```

---

## ⚙️ Setup & Installation

### 1. Install dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Environment Variables

Create a `.env` file in the `backend/` folder:

```env
MONGO_URI=mongodb+srv://<user>:<password>@trainsdata.exem1wb.mongodb.net/
```

> If `MONGO_URI` is not set, the app automatically falls back to **Local MongoDB Compass** at `mongodb://localhost:27017/`

### 3. MongoDB Collections

- **Database:** `Security_db`

| Collection | Documents | Description |
|---|---|---|
| `processed_events` | 1800 | Raw security events |
| `prediction_results` | 1800 | IF_v2 ML predictions |
| `users` | 2+ | Admin + registered users |
| `incidents` | 718 | M3 — Risk incidents |

### 4. Run the server

```bash
python app.py
```

Server runs at: `http://127.0.0.1:5000`

---

## 🧪 Running Tests

**Requires Flask to be running in a separate terminal first.**

```bash
# Run all 41 tests (M1 + M2 + M3 + M4)
python -m pytest tests/test_unit_plan.py -v

# Quick summary output
python -m pytest tests/test_unit_plan.py -q

# Run only a specific milestone
python -m pytest tests/test_unit_plan.py::TestMilestone1DataPipeline -v
python -m pytest tests/test_unit_plan.py::TestMilestone2MLPrediction -v
python -m pytest tests/test_unit_plan.py::TestMilestone3RiskAndIncidents -v
python -m pytest tests/test_unit_plan.py::TestMilestone4DashboardAPIs -v

# Run a single specific test
python -m pytest tests/test_unit_plan.py::TestMilestone1DataPipeline::test_tc01_dataset_loading -v
```

**Result: 41/41 PASSED ✅**

---

## 🔐 Auth APIs

Base prefix: `/api`

### POST `/api/signup`

Register a new user.

**Request:**
```json
{
  "username": "yourname",
  "email": "you@example.com",
  "password": "yourpass"
}
```

**Response:**
```json
{ "message": "User registered successfully." }
```

---

### POST `/api/login`

Login with username or email.

**Request:**
```json
{
  "identity": "admin",
  "password": "admin123"
}
```

**Response:**
```json
{ "message": "Login successful", "username": "admin" }
```

> Default admin: `username: admin` | `password: admin123`

---

## 📡 Milestone 1 — Security Events APIs

Base prefix: `/api`

### GET `/api/events`

Returns all 1800 security events.

**Query Parameters:**

| Param | Example | Description |
|---|---|---|
| `severity` | `Critical` | Filter by severity level |
| `event_type` | `Brute Force` | Filter by event type |
| `limit` | `50` | Max records to return |

**Response:**
```json
[
  {
    "event_id": "EVT00001",
    "event_type": "Brute Force",
    "severity": "CRITICAL",
    "source_ip": "192.168.1.10",
    "destination_ip": "10.0.0.5",
    "timestamp": "2025-08-01 10:01:00",
    "username": "alice",
    "status": "Failed",
    "is_high_risk": true
  }
]
```

---

### GET `/api/stats`

Returns dashboard KPI statistics.

**Response:**
```json
{
  "totalEvents": 1800,
  "criticalThreats": 346,
  "highSeverityAlerts": 573,
  "vulnerabilities": 1373,
  "activeIncidents": 905
}
```

---

### GET `/api/threats`

Returns threat type distribution.

**Response:**
```json
[
  { "event_type": "Brute Force", "count": 195 },
  { "event_type": "Malware Detection", "count": 182 }
]
```

---

## 🤖 Milestone 2 — ML Prediction APIs

Base prefix: `/api`

### GET `/api/predictions`

Returns all 1800 IF_v2 ML predictions.

**Response:**
```json
[
  {
    "event_id": "EVT00001",
    "prediction": "Suspicious",
    "confidence_score": 91,
    "anomaly_score": -0.72,
    "severity": "Critical",
    "threat_type": "Brute Force",
    "model_version": "IF_v2",
    "prediction_timestamp": "2026-08-18T21:13:23"
  }
]
```

---

### GET `/api/predictions/<event_id>`

Returns the prediction for a single event.

**Example:** `/api/predictions/EVT00001`

**Response:**
```json
{
  "event_id": "EVT00001",
  "prediction": "Suspicious",
  "confidence_score": 91,
  "anomaly_score": -0.72,
  "model_version": "IF_v2"
}
```

---

### GET `/api/anomalies`

Returns only `Suspicious` events (1309 events).

**Response:** Same structure as `/api/predictions` but filtered to `prediction = "Suspicious"`.

---

### GET `/api/model-performance`

Returns Isolation Forest model statistics.

**Response:**
```json
{
  "model_version": "IF_v2",
  "algorithm": "Isolation Forest",
  "total_events": 1800,
  "suspicious_count": 1309,
  "normal_count": 491,
  "suspicious_percentage": 72.7,
  "feature_count": 46,
  "note": "Unsupervised model — accuracy/F1 not applicable"
}
```

---

### GET `/api/threat-summary`

Returns threat breakdown by severity and type.

**Response:**
```json
{
  "by_severity": {
    "Critical": 346,
    "High": 573,
    "Medium": 476,
    "Low": 405
  },
  "by_type": {
    "Brute Force": 195,
    "Malware Detection": 182
  }
}
```

---

### POST `/api/predict`

Real-time ML prediction for a new security event.

**Request:**
```json
{
  "event_type": "Brute Force",
  "failed_login_attempts": 18,
  "cvss_score": 8.9,
  "severity": "High",
  "status": "Failed",
  "protocol": "SSH",
  "malware_detected": "No",
  "department": "IT",
  "vulnerability_id": "CVE-2023-1234"
}
```

**Response:**
```json
{
  "prediction": "Suspicious",
  "confidence_score": 91,
  "severity": "High",
  "threat_type": "Brute Force",
  "anomaly_score": -0.72,
  "model_version": "IF_v2"
}
```

---

## 🎯 Milestone 3 — Risk Intelligence APIs

Base prefix: `/api/v1`

---

### GET `/api/v1/risk/summary`

Returns overall risk distribution and statistics across all 1800 events.

**URL:** `http://127.0.0.1:5000/api/v1/risk/summary`

**Response:**
```json
{
  "total_events": 1800,
  "avg_risk_score": 52.4,
  "risk_distribution": {
    "Critical": 1,
    "High": 506,
    "Moderate": 905,
    "Medium": 380,
    "Low": 8
  },
  "top_threat_types": {
    "Brute Force": 195,
    "Malware Detection": 182,
    "Phishing Email": 175
  },
  "ioc_matched_count": 45,
  "correlated_events": 1640
}
```

---

### GET `/api/v1/risk/high`

Returns High and Critical risk events sorted by risk score (highest first).

**URL:** `http://127.0.0.1:5000/api/v1/risk/high`

**Query Parameters:**

| Param | Example | Description |
|---|---|---|
| `risk_class` | `Critical` | Filter: Critical / High / Moderate / Medium / Low |
| `limit` | `50` | Max records (default 100) |
| `offset` | `0` | Pagination offset |

**Response:**
```json
{
  "total": 507,
  "offset": 0,
  "limit": 100,
  "events": [
    {
      "event_id": "EVT00572",
      "event_type": "Malware Detection",
      "risk_score": 84.0,
      "risk_class": "Critical",
      "priority": 1,
      "severity": "Critical",
      "asset_name": "Firewall",
      "asset_id": "AST004",
      "criticality": "Critical",
      "username": "alice",
      "source_ip": "146.212.96.249",
      "timestamp": "2025-08-02 23:35:00",
      "mitre_id": "T1110",
      "technique_name": "Brute Force",
      "tactic": "Credential Access",
      "ioc_match": false,
      "cvss_score": 9.0,
      "correlation_id": "CORR-0001",
      "is_correlated": true,
      "correlated_event_count": 5
    }
  ]
}
```

---

### POST `/api/v1/risk/calculate`

Real-time risk score calculation for a new security event.

**URL:** `http://127.0.0.1:5000/api/v1/risk/calculate`

**Risk Formula:**
```
Risk Score =
  (Threat Severity   × 25%) +
  (ML Confidence     × 25%) +
  (Asset Criticality × 20%) +
  (Vulnerability     × 20%) +
  (Threat Intel/IOC  × 10%)
```

**Request:**
```json
{
  "event_type": "Brute Force",
  "severity": "Critical",
  "confidence_score": 92,
  "asset_criticality": "Critical",
  "cvss_score": 9.8,
  "ioc_match": true
}
```

**Response:**
```json
{
  "risk_score": 97.0,
  "risk_class": "Critical",
  "priority": 1,
  "breakdown": {
    "threat_severity_score": 100,
    "ml_confidence_score": 92,
    "asset_criticality_score": 100,
    "vulnerability_score": 98.0,
    "threat_intelligence_score": 100
  },
  "weights": {
    "threat_severity": "25%",
    "ml_confidence": "25%",
    "asset_criticality": "20%",
    "vulnerability": "20%",
    "threat_intelligence": "10%"
  },
  "recommendation": [
    "Temporarily lock the affected user account",
    "Investigate and block the source IP address",
    "Enable Multi-Factor Authentication (MFA)",
    "Cross-reference IOC with threat intelligence platforms",
    "Escalate immediately to senior security analyst"
  ]
}
```

**Risk Classification:**

| Score | Level |
|---|---|
| 81–100 | Critical |
| 61–80 | High |
| 41–60 | Moderate |
| 21–40 | Medium |
| 0–20 | Low |

---

### GET `/api/v1/incidents`

Returns all 718 incidents sorted by priority (Critical first).

**URL:** `http://127.0.0.1:5000/api/v1/incidents`

**Query Parameters:**

| Param | Example | Description |
|---|---|---|
| `priority` | `Critical` | Filter by priority level |
| `status` | `Open` | Filter by status |
| `limit` | `50` | Max records (default 100) |
| `offset` | `0` | Pagination offset |

**Response:**
```json
{
  "total": 718,
  "offset": 0,
  "limit": 100,
  "incidents": [
    {
      "incident_id": "INC-0001",
      "correlation_id": "CORR-0001",
      "event_ids": ["EVT00572", "EVT00171", "EVT00893"],
      "event_count": 3,
      "threat_type": "Malware Detection",
      "risk_score": 84.0,
      "risk_class": "Critical",
      "priority": "Critical",
      "priority_rank": 1,
      "asset_id": "AST004",
      "asset_name": "Firewall",
      "criticality": "Critical",
      "affected_user": "alice",
      "source_ip": "146.212.96.249",
      "destination_ip": "10.0.7.106",
      "mitre_technique": "T1110",
      "technique_name": "Brute Force",
      "tactic": "Credential Access",
      "ioc_match": false,
      "cvss_score": 9.0,
      "cve_id": "CVE-2024-1045",
      "status": "Open",
      "recommendation": [
        "Immediately isolate the affected endpoint from the network",
        "Run a full malware scan using updated signatures",
        "Investigate the malware file hash in threat intelligence",
        "Escalate immediately to senior security analyst"
      ],
      "created_at": "2026-09-05T15:45:00Z"
    }
  ]
}
```

---

### GET `/api/v1/incidents/<incident_id>`

Returns complete details for a single incident.

**URL:** `http://127.0.0.1:5000/api/v1/incidents/INC-0001`

**Response:** Same structure as a single object from `/api/v1/incidents` above.

---

### GET `/api/v1/attack-chains`

Returns correlated event groups that form possible attack chains.

**URL:** `http://127.0.0.1:5000/api/v1/attack-chains`

**Query Parameters:**

| Param | Example | Description |
|---|---|---|
| `min_events` | `2` | Minimum events in chain (default 2) |
| `limit` | `50` | Max chains to return (default 50) |

**Response:**
```json
{
  "total": 328,
  "limit": 50,
  "chains": [
    {
      "correlation_id": "CORR-0001",
      "event_count": 5,
      "event_ids": ["EVT00572", "EVT00171", "EVT00893", "EVT01024", "EVT01340"],
      "threat_types": ["Failed Login", "Brute Force", "Privilege Escalation"],
      "max_risk_score": 84.0,
      "risk_class": "Critical",
      "first_event_time": "2025-08-02 23:10:00",
      "last_event_time": "2025-08-02 23:35:00",
      "affected_users": ["alice", "root"],
      "source_ips": ["146.212.96.249"],
      "asset_ids": ["AST004"],
      "mitre_techniques": ["T1110", "T1078"],
      "tactics": ["Credential Access"],
      "ioc_involved": false
    }
  ]
}
```

> **Attack Chain Example:**
> `Failed Login → Brute Force → Privilege Escalation` — all from same IP within 30 min window = possible multi-stage attack.

---

### GET `/api/v1/recommendations/<incident_id>`

Returns actionable response recommendations for a specific incident.

**URL:** `http://127.0.0.1:5000/api/v1/recommendations/INC-0001`

**Response:**
```json
{
  "incident_id": "INC-0001",
  "threat_type": "Malware Detection",
  "risk_score": 84.0,
  "priority": "Critical",
  "recommendation": [
    "Immediately isolate the affected endpoint from the network",
    "Run a full malware scan using updated signatures",
    "Investigate the malware file hash in threat intelligence",
    "Check for lateral movement from the affected system",
    "Review all processes spawned before and after detection",
    "Preserve forensic evidence before remediation",
    "Cross-reference IOC with threat intelligence platforms (VirusTotal, OTX)",
    "Escalate immediately to senior security analyst",
    "Consider activating Incident Response (IR) plan",
    "Notify management and CISO"
  ]
}
```

**Recommendation mapping by event type:**

| Event Type | Key Recommendations |
|---|---|
| Brute Force | Lock account, block IP, enable MFA, review auth logs |
| Malware Detection | Isolate endpoint, full scan, check lateral movement |
| Phishing Email | Quarantine email, block sender, alert users |
| SQL Injection | Block IP at WAF, sanitize inputs, check DB logs |
| Privilege Escalation | Revoke privileges, audit actions, patch vulnerability |
| Port Scan | Block source IP, review firewall rules |
| USB Device | Scan device, check data copied, enforce policy |

---

## 📊 Complete API Reference

### Milestone 1 — `/api/`

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/signup` | Register new user |
| POST | `/api/login` | User login |
| GET | `/api/events` | All security events |
| GET | `/api/events?severity=Critical` | Filter events by severity |
| GET | `/api/events?event_type=Brute Force` | Filter by type |
| GET | `/api/stats` | Dashboard KPIs |
| GET | `/api/threats` | Threat distribution |

### Milestone 2 — `/api/`

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/predictions` | All ML predictions (1800) |
| GET | `/api/predictions/<event_id>` | Single prediction |
| GET | `/api/anomalies` | Suspicious events only |
| GET | `/api/model-performance` | IF_v2 model stats |
| GET | `/api/threat-summary` | Threat breakdown |
| POST | `/api/predict` | Real-time ML prediction |

### Milestone 3 — `/api/v1/`

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/risk/summary` | Risk distribution summary |
| GET | `/api/v1/risk/high` | High & Critical risk events |
| POST | `/api/v1/risk/calculate` | Real-time risk score + recommendation |
| GET | `/api/v1/incidents` | All 718 incidents |
| GET | `/api/v1/incidents/<incident_id>` | Single incident details |
| GET | `/api/v1/attack-chains` | Correlated attack chains |
| GET | `/api/v1/recommendations/<incident_id>` | Response recommendations |

---

## 🤖 ML Model Details

| Property | Value |
|---|---|
| Algorithm | Isolation Forest (unsupervised) |
| Version | IF_v2 |
| Training data | 1800 security events |
| Features | 46 (one-hot + scaled) |
| Suspicious events | 1309 (72.7%) |
| Normal events | 491 (27.3%) |
| Model file | `backend/models/isolation_forest.pkl` |

---

## 🗄️ Database Structure

```
Security_db (MongoDB Atlas)
├── processed_events     → 1800 security events (source of truth)
├── prediction_results   → 1800 ML predictions (IF_v2)
├── users                → admin + registered users
└── incidents            → 718 M3 risk incidents
```

---

## 📊 Project Stats

```
Total Events        : 1800
Critical Threats    : 346
High Severity Alerts: 573
Vulnerabilities     : 1373
ML Suspicious Events: 1309 (72.7%)
Risk Incidents      : 718
Attack Chains       : 328
Correlated Events   : 1640
```

---

## 🔗 Related

- **Branch:** `main` (merged from Prasanth branch)
- **Model version:** `IF_v2`
- **Database:** `Security_db` (Atlas + Local Compass fallback)
- **Tests:** 41/41 tests passing

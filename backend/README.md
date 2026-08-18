# 🛡️ AI Security Threat Detection — Backend

**Milestone 2 | Team A | Backend**

A Flask-based backend for real-time security threat detection using Machine Learning (Isolation Forest). Connects to MongoDB (`Security_db`) and exposes REST APIs for the frontend dashboard.

---

## 📁 Project Structure

```
backend/
├── app.py                          # Flask application entry point
├── db.py                           # MongoDB connection & helpers
├── requirements.txt                # Python dependencies
├── feature_selection.md            # M2 Task 1 — Feature documentation
├── upload_to_mongo.py              # Utility: upload CSV to MongoDB
│
├── routes/
│   ├── auth.py                     # POST /api/login, POST /api/signup
│   ├── events.py                   # GET /events
│   ├── stats.py                    # GET /stats
│   ├── threats.py                  # GET /threats
│   └── prediction_routes.py        # All ML prediction APIs
│
├── ml/
│   ├── anomaly_detection.py        # Original IF_v1 training script
│   ├── retrain_pipeline.py         # IF_v2 full retrain pipeline
│   ├── Store_predictions.py        # Store predictions to MongoDB
│   ├── model_evaluation.py         # Unsupervised model stats
│   └── test.py                     # Dataset diagnostics
│
├── models/
│   ├── isolation_forest.pkl        # Trained IF_v2 model
│   └── feature_columns.json        # 46 ML feature column names
│
├── data/
│   ├── processed/
│   │   ├── Security_db.processed_events.csv   # Main event dataset (1800 rows)
│   │   ├── ml_features.csv                    # ML feature matrix (46 features)
│   │   └── prediction_results.csv             # IF_v2 predictions backup
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
│   └── ...
│
└── tests/
    └── test_apis.py                # M2 Task 9 — API tests (69/69 passing)
```

---

## ⚙️ Setup & Installation

### 1. Install dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Environment Variables (optional)

Create a `.env` file in the `backend/` folder:

```env
MONGO_URI=mongodb+srv://<user>:<password>@trainsdata.exem1wb.mongodb.net/
```

> If `MONGO_URI` is not set, the app automatically uses **Local MongoDB Compass** at `mongodb://localhost:27017/`

### 3. MongoDB Setup

- **Database:** `Security_db`
- **Collections:**
  - `processed_events` — 1800 security events
  - `prediction_results` — 1800 IF_v2 predictions
  - `users` — admin + registered users

### 4. Run the server

```bash
python app.py
```

Server runs at: `http://127.0.0.1:5000`

---

## 🔁 Retrain the ML Model

```bash
python backend/ml/retrain_pipeline.py
```

This will:
1. Load `Security_db.processed_events.csv`
2. Preprocess 46 features
3. Train Isolation Forest (IF_v2)
4. Save `isolation_forest.pkl`
5. Generate 1800 predictions
6. Store predictions in `Security_db.prediction_results`

---

## 🔐 Auth APIs

### POST `/api/signup`
```json
{
  "username": "yourname",
  "email": "you@example.com",
  "password": "yourpass"
}
```

### POST `/api/login`
```json
{
  "identity": "admin",
  "password": "admin123"
}
```

> Default admin: `username: admin` | `password: admin123`

---

## 📡 All API Endpoints

### Security Events

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/events` | All 1800 security events |
| GET | `/events?severity=Critical` | Filter by severity |
| GET | `/events?event_type=Brute Force` | Filter by event type |
| GET | `/stats` | Dashboard statistics |
| GET | `/threats` | Threat type breakdown |

### ML Predictions

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/predictions` | All 1800 IF_v2 predictions |
| GET | `/predictions/<event_id>` | Single event prediction |
| GET | `/anomalies` | All Suspicious events (1309) |
| GET | `/model-performance` | Model stats (unsupervised) |
| GET | `/threat-summary` | Summary by severity & type |
| POST | `/predict` | Real-time prediction for new event |

### POST `/predict` — Example

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

## 🤖 ML Model Details

| Property | Value |
|----------|-------|
| Algorithm | Isolation Forest (unsupervised) |
| Version | IF_v2 |
| Training data | `Security_db.processed_events.csv` (1800 rows) |
| Features | 46 (one-hot encoded + scaled numerics) |
| Normal events | 491 (27.3%) |
| Suspicious events | 1309 (72.7%) |
| Model file | `backend/models/isolation_forest.pkl` |

### Key Features Used

- `failed_login_attempts`, `cvss_score`, `severity_score` *(scaled)*
- `event_type_*` *(one-hot: 10 types)*
- `protocol_*` *(HTTP, HTTPS, SMB, SSH, TCP)*
- `status_*` *(Blocked, Detected, Failed, Success)*
- `severity_*` *(Critical, High, Low, Medium)*
- `malware_detected_*`, `department_*`, `vulnerability_id_*`
- `threat_feed_match_false`, `technique_name_*`, `tactic_*`

> **Note:** Isolation Forest is unsupervised — Accuracy, Precision, Recall, F1 are not applicable without ground-truth labels.

---

## 🧪 Running Tests

```bash
python backend/tests/test_apis.py
```

**Result: 69/69 tests passing ✅**

Tests cover all 11 endpoint sections including GET filters, POST /predict, auth login, and error handling (404).

---

## 🗄️ Database Structure

```
Security_db (MongoDB)
├── processed_events     → 1800 security events (source of truth)
├── prediction_results   → 1800 ML predictions (IF_v2)
└── users                → admin + registered users
```

---

## 📊 Stats at a Glance

```
Total Events      : 1800
Critical Threats  : 346
High Severity     : 573
Vulnerabilities   : 1373
Active Incidents  : 905
Suspicious (ML)   : 1309
Normal (ML)       : 491
```

---

## 🔗 Related

- **Branch:** `Prasanth` (Backend Team)
- **Model version:** `IF_v2`
- **Database:** `Security_db` (Atlas + Local Compass fallback)

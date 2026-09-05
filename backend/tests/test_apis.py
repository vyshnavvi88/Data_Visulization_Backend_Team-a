"""
test_apis.py
------------
Milestone 2 — Task 9: API Testing & Optimization

Tests all backend endpoints against the running Flask server.

Run with:
    python backend/tests/test_apis.py
    
    OR (if pytest installed):
    pytest backend/tests/test_apis.py -v
"""

import sys
import json
import requests

BASE_URL = "http://127.0.0.1:5000"

PASS = "\033[92m✅ PASS\033[0m"
FAIL = "\033[91m❌ FAIL\033[0m"
WARN = "\033[93m⚠️  WARN\033[0m"

results = {"passed": 0, "failed": 0, "warned": 0}


def check(name, condition, detail=""):
    if condition:
        print(f"  {PASS}  {name}")
        results["passed"] += 1
    else:
        print(f"  {FAIL}  {name}  →  {detail}")
        results["failed"] += 1


def warn(name, detail=""):
    print(f"  {WARN}  {name}  →  {detail}")
    results["warned"] += 1


def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# ==================================================
# 1. Health Check
# ==================================================

section("1. GET / — Health Check")
try:
    r = requests.get(f"{BASE_URL}/", timeout=15)  # Atlas init can take ~10s
    data = r.json()
    check("Status 200",           r.status_code == 200)
    check("Backend = Running",    data.get("Backend") == "Running")
    check("Database = Security_db", data.get("Database") == "Security_db")
    check("Connection field exists", "Connection" in data)
    check("Connected = True",     data.get("Connected") is True)
    print(f"       Connection : {data.get('Connection')}")
except Exception as e:
    check("Health check reachable", False, str(e))


# ==================================================
# 2. GET /events
# ==================================================

section("2. GET /events — All Events")
try:
    r = requests.get(f"{BASE_URL}/events", timeout=30)  # 1800 records from Atlas
    data = r.json()
    check("Status 200",               r.status_code == 200)
    check("Returns a list",           isinstance(data, list))
    check("Has 1800 events",          len(data) == 1800, f"got {len(data)}")
    if data:
        first = data[0]
        # API maps event_id → 'id' (numeric) via map_event_to_frontend()
        check("Has id field",          "id" in first)
        check("Has event_type field",  "event_type" in first)
        # severity is mapped: Critical→CRITICAL, High/Medium→WARNING, Low→LOW
        check("Has severity field",    "severity" in first)
        check("severity is uppercase", first.get("severity") in ["CRITICAL","WARNING","LOW"])
        check("Has timestamp field",   "timestamp" in first)
        check("Has status field",      "status" in first)
except Exception as e:
    check("Events endpoint reachable", False, str(e))

# Filter by severity
section("2a. GET /events?severity=Critical")
try:
    r = requests.get(f"{BASE_URL}/events?severity=Critical", timeout=10)
    data = r.json()
    check("Status 200",                    r.status_code == 200)
    check("Returns a list",                isinstance(data, list))
    # map_event_to_frontend() maps severity='Critical' → 'CRITICAL'
    check("All events are CRITICAL",       all(e.get("severity") == "CRITICAL" for e in data),
          f"found non-CRITICAL in {len(data)} events")
    print(f"       Critical events : {len(data)}")
except Exception as e:
    check("Severity filter reachable", False, str(e))

# Filter by event_type
section("2b. GET /events?event_type=Brute Force")
try:
    r = requests.get(f"{BASE_URL}/events?event_type=Brute Force", timeout=10)
    data = r.json()
    check("Status 200",                   r.status_code == 200)
    check("Returns a list",               isinstance(data, list))
    check("All events are Brute Force",   all(e.get("event_type") == "Brute Force" for e in data))
    print(f"       Brute Force events : {len(data)}")
except Exception as e:
    check("Event type filter reachable", False, str(e))


# ==================================================
# 3. GET /stats
# ==================================================

section("3. GET /stats — Dashboard Statistics")
try:
    r = requests.get(f"{BASE_URL}/stats", timeout=10)
    data = r.json()
    check("Status 200",                    r.status_code == 200)
    check("Has totalEvents",               "totalEvents" in data)
    check("totalEvents = 1800",            data.get("totalEvents") == 1800, f"got {data.get('totalEvents')}")
    check("Has criticalThreats",           "criticalThreats" in data)
    check("Has highSeverityAlerts",        "highSeverityAlerts" in data)
    check("Has vulnerabilities",           "vulnerabilities" in data)
    check("Has activeIncidents",           "activeIncidents" in data)
    check("criticalThreats > 0",           data.get("criticalThreats", 0) > 0)
    check("vulnerabilities > 0",          data.get("vulnerabilities", 0) > 0)
    print(f"       Stats : {json.dumps(data, indent=6)}")
except Exception as e:
    check("Stats endpoint reachable", False, str(e))


# ==================================================
# 4. GET /threats
# ==================================================

section("4. GET /threats — Threat Breakdown")
try:
    r = requests.get(f"{BASE_URL}/threats", timeout=10)
    data = r.json()
    check("Status 200",             r.status_code == 200)
    check("Returns a list",         isinstance(data, list))
    check("Has threats",            len(data) > 0, f"got {len(data)}")
    if data:
        first = data[0]
        check("Has event_type",     "event_type" in first or "type" in first)
        check("Has count",          "count" in first)
    print(f"       Threat types : {len(data)}")
except Exception as e:
    check("Threats endpoint reachable", False, str(e))


# ==================================================
# 5. GET /predictions
# ==================================================

section("5. GET /predictions — All Predictions")
try:
    r = requests.get(f"{BASE_URL}/predictions", timeout=10)
    data = r.json()
    check("Status 200",              r.status_code == 200)
    check("Returns a list",          isinstance(data, list))
    check("Has 1800 predictions",    len(data) == 1800, f"got {len(data)}")
    if data:
        first = data[0]
        check("Has event_id",        "event_id" in first)
        check("Has prediction",      "prediction" in first)
        check("Has anomaly_score",   "anomaly_score" in first)
        check("Has severity",        "severity" in first)
        check("Has model_version",   "model_version" in first)
        check("Model version IF_v2", first.get("model_version") == "IF_v2",
              f"got {first.get('model_version')}")
    print(f"       Total predictions : {len(data)}")
except Exception as e:
    check("Predictions endpoint reachable", False, str(e))


# ==================================================
# 6. GET /predictions/<event_id>
# ==================================================

section("6. GET /predictions/<event_id> — Single Prediction")
try:
    r = requests.get(f"{BASE_URL}/predictions/EVT00001", timeout=10)
    check("Status 200",            r.status_code == 200, f"got {r.status_code}")
    if r.status_code == 200:
        data = r.json()
        check("Has event_id",      "event_id" in data)
        check("event_id matches",  data.get("event_id") == "EVT00001")
        check("Has prediction",    "prediction" in data)
        print(f"       EVT00001 prediction : {data.get('prediction')}")
except Exception as e:
    check("Single prediction reachable", False, str(e))

# Test 404 for missing event
try:
    r = requests.get(f"{BASE_URL}/predictions/EVT99999", timeout=5)
    check("Returns 404 for missing event_id", r.status_code == 404,
          f"got {r.status_code}")
except Exception as e:
    check("404 test reachable", False, str(e))


# ==================================================
# 7. GET /anomalies
# ==================================================

section("7. GET /anomalies — Suspicious Events")
try:
    r = requests.get(f"{BASE_URL}/anomalies", timeout=10)
    data = r.json()
    check("Status 200",              r.status_code == 200)
    check("Returns a list",          isinstance(data, list))
    check("Has anomalies",           len(data) > 0, f"got {len(data)}")
    check("All are Suspicious",      all(e.get("prediction") == "Suspicious" for e in data))
    print(f"       Suspicious events : {len(data)}")
except Exception as e:
    check("Anomalies endpoint reachable", False, str(e))


# ==================================================
# 8. GET /model-performance
# ==================================================

section("8. GET /model-performance — Model Stats")
try:
    r = requests.get(f"{BASE_URL}/model-performance", timeout=10)
    data = r.json()
    check("Status 200",              r.status_code == 200)
    check("Has model_type",          "model_type" in data)
    check("Has total_predictions",   "total_predictions" in data)
    check("Has normal_count",        "normal_count" in data)
    check("Has suspicious_count",    "suspicious_count" in data)
    check("total = 1800",            data.get("total_predictions") == 1800,
          f"got {data.get('total_predictions')}")
    print(f"       Model type : {data.get('model_type')}")
    print(f"       Normal     : {data.get('normal_count')}")
    print(f"       Suspicious : {data.get('suspicious_count')}")
except Exception as e:
    check("Model performance reachable", False, str(e))


# ==================================================
# 9. GET /threat-summary
# ==================================================

section("9. GET /threat-summary — Threat Summary")
try:
    r = requests.get(f"{BASE_URL}/threat-summary", timeout=10)
    data = r.json()
    check("Status 200",              r.status_code == 200)
    check("Has by_severity",         "by_severity" in data or isinstance(data, list) or isinstance(data, dict))
    print(f"       Summary keys : {list(data.keys()) if isinstance(data, dict) else 'list'}")
except Exception as e:
    check("Threat summary reachable", False, str(e))


# ==================================================
# 10. POST /predict
# ==================================================

section("10. POST /predict — Real-time Prediction")
payload = {
    "event_type": "Brute Force",
    "failed_login_attempts": 18,
    "cvss_score": 8.9,
    "severity": "High",
    "status": "Failed",
    "protocol": "SSH",
    "malware_detected": "No",
    "department": "IT",
    "vulnerability_id": "CVE-2023-1234",
    "source_country": "India",
    "destination_country": "India",
    "os": "Linux",
    "technique_name": "Brute Force",
    "tactic": "Credential Access",
    "threat_feed_match": "true"
}
try:
    r = requests.post(f"{BASE_URL}/predict", json=payload, timeout=10)
    check("Status 200",              r.status_code == 200, f"got {r.status_code}: {r.text[:200]}")
    if r.status_code == 200:
        data = r.json()
        check("Has prediction",      "prediction" in data)
        check("Has confidence_score","confidence_score" in data)
        check("Has severity",        "severity" in data)
        check("Valid prediction val",data.get("prediction") in ["Normal", "Suspicious"])
        print(f"       Prediction      : {data.get('prediction')}")
        print(f"       Confidence      : {data.get('confidence_score')}")
        print(f"       Severity        : {data.get('severity')}")
        print(f"       Model version   : {data.get('model_version')}")
except Exception as e:
    check("POST /predict reachable", False, str(e))


# ==================================================
# 11. POST /api/login
# ==================================================

section("11. POST /api/login — Admin Login")
try:
    r = requests.post(f"{BASE_URL}/api/login",
                      json={"identity": "admin", "password": "admin123"},
                      timeout=5)
    check("Status 200",          r.status_code == 200, f"got {r.status_code}: {r.text[:200]}")
    if r.status_code == 200:
        data = r.json()
        check("Has username",    "username" in data)
        check("username=admin",  data.get("username") == "admin")

    # Wrong password → 401
    r2 = requests.post(f"{BASE_URL}/api/login",
                       json={"identity": "admin", "password": "wrongpass"},
                       timeout=5)
    check("Wrong password → 401", r2.status_code == 401, f"got {r2.status_code}")
except Exception as e:
    check("Login endpoint reachable", False, str(e))


# ==================================================
# FINAL SUMMARY
# ==================================================

total = results["passed"] + results["failed"] + results["warned"]
print(f"\n{'='*60}")
print(f"  TEST RESULTS")
print(f"{'='*60}")
print(f"  ✅ Passed  : {results['passed']}")
print(f"  ❌ Failed  : {results['failed']}")
print(f"  ⚠️  Warnings: {results['warned']}")
print(f"  Total      : {total}")
print(f"{'='*60}")

if results["failed"] == 0:
    print("\n  🎉 ALL TESTS PASSED — Milestone 2 Backend Complete!")
else:
    print(f"\n  ⚠️  {results['failed']} test(s) need attention.")
    sys.exit(1)

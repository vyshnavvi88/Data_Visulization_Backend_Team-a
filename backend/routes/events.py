from flask import Blueprint, jsonify, request
from db import get_events_data, insert_event_data, load_predictions, update_event_status

events_bp = Blueprint("events", __name__)

def map_event_to_frontend(event, predictions_map=None):
    # Determine predictions if map is provided
    evt_id = event.get("event_id", "")
    pred_info = predictions_map.get(evt_id, {}) if predictions_map else {}
    
    # Raw dataset fields (making sure they are present and have correct types)
    failed_login = event.get("failed_login_attempts", 0)
    try:
        failed_login = int(float(failed_login)) if failed_login not in ["", None, "None"] else 0
    except (ValueError, TypeError):
        failed_login = 0
        
    malware_detected_raw = str(event.get("malware_detected", "")).lower()
    malware_detected_bool = malware_detected_raw in ["yes", "true", "1"]
    
    cvss = event.get("cvss_score", 0.0)
    try:
        cvss = float(cvss) if cvss not in ["", None, "None"] else 0.0
    except (ValueError, TypeError):
        cvss = 0.0
        
    risk = event.get("risk_score", 0.0)
    try:
        risk = float(risk) if risk not in ["", None, "None"] else 0.0
    except (ValueError, TypeError):
        risk = 0.0
        
    is_high_risk = event.get("is_high_risk")
    if isinstance(is_high_risk, str):
        is_high_risk_bool = is_high_risk.lower() == "true"
    else:
        is_high_risk_bool = bool(is_high_risk)
        
    # Uppercase severity (expected by frontend charts & filters)
    severity_raw = str(event.get("severity", "")).upper()
    if severity_raw in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "WARNING"]:
        severity_title = severity_raw
    else:
        severity_title = "LOW"
        
        
    # Legacy mapped keys
    try:
        numeric_id = int(''.join(filter(str.isdigit, str(evt_id))))
    except ValueError:
        numeric_id = 0

    timestamp_str = event.get("timestamp", "")
    time_str = ""
    if timestamp_str and " " in str(timestamp_str):
        time_str = str(timestamp_str).split(" ")[1]
    elif timestamp_str and "T" in str(timestamp_str):
        time_str = str(timestamp_str).split("T")[1][:8]
    else:
        time_str = str(timestamp_str)
        
    status_raw = str(event.get("event_status", "")).lower()
    if status_raw in ["blocked", "failed"]:
        status = "RESOLVED"
    else:
        status = "UNRESOLVED"
        
    # Construct complete dictionary with both raw keys, legacy mapped keys, and ML prediction keys
    return {
        # Raw dataset fields
        "event_id": evt_id,
        "timestamp": timestamp_str,
        "source_ip": event.get("source_ip", ""),
        "destination_ip": event.get("destination_ip", ""),
        "username": event.get("username", ""),
        "event_type": event.get("event_type", ""),
        "severity": severity_title,
        "failed_login_attempts": failed_login,
        "malware_detected": malware_detected_bool,
        "vulnerability_id": event.get("vulnerability_id", ""),
        "cvss_score": cvss,
        "asset_name": event.get("asset_name", ""),
        "risk_score": risk,
        "is_high_risk": is_high_risk_bool,
        
        # ML prediction results (enriched)
        "prediction": pred_info.get("prediction", "Normal"),
        "anomaly_score": pred_info.get("anomaly_score", 0.0),
        "threat_level": pred_info.get("threat_level", "Low"),
        "confidence_score": pred_info.get("confidence_score", 0),
        
        # Legacy frontend fields (backward compatibility)
        "id": numeric_id,
        "time": time_str,
        "name": event.get("event_type", "Unknown Event"),
        "source": event.get("username", "System"),
        "target": event.get("asset_name", ""),
        "status": status
    }

@events_bp.route("/events", methods=["GET", "POST"])
def manage_events():
    if request.method == "POST":
        data = request.json
        if data:
            db_data = data.copy()
            if "name" in data and "event_type" not in data:
                db_data["event_type"] = data["name"]
            if "source" in data and "username" not in data:
                db_data["username"] = data["source"]
            if "target" in data and "asset_name" not in data:
                db_data["asset_name"] = data["target"]
            if "status" in data and "event_status" not in data:
                db_data["event_status"] = "Blocked" if data["status"] == "RESOLVED" else "Success"
            if "id" in data and "event_id" not in data:
                db_data["event_id"] = f"EVT{int(data['id']):05d}"
            
            if "severity" in data and "severity" not in db_data:
                sev = data["severity"]
                if sev == "CRITICAL":
                    db_data["severity"] = "Critical"
                elif sev == "WARNING":
                    db_data["severity"] = "High"
                else:
                    db_data["severity"] = "Low"

            insert_event_data(db_data)
            db_data.pop("_id", None)
            return jsonify({"message": "Event added successfully", "event": db_data}), 201
        return jsonify({"error": "No data provided"}), 400

    raw_events = get_events_data()
    preds = load_predictions()
    mapped_events = [map_event_to_frontend(evt, preds) for evt in raw_events]
    return jsonify(mapped_events)

@events_bp.route("/api/events/<event_id>/resolve", methods=["POST"])
@events_bp.route("/events/<event_id>/resolve", methods=["POST"])
def resolve_event(event_id):
    success = update_event_status(event_id, "Blocked")
    if success:
        return jsonify({"message": f"Event {event_id} marked as resolved/blocked."}), 200
    else:
        return jsonify({"error": f"Failed to update event {event_id} or event not found."}), 404
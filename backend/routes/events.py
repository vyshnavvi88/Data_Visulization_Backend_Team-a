from flask import Blueprint, jsonify, request
from db import get_events_data, insert_event_data

events_bp = Blueprint("events", __name__)

def map_event_to_frontend(event):
    evt_id_str = event.get("event_id", "")
    try:
        numeric_id = int(''.join(filter(str.isdigit, str(evt_id_str))))
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
    
    raw_severity = str(event.get("severity", "")).lower()
    if raw_severity == "critical":
        severity = "CRITICAL"
    elif raw_severity in ["high", "medium"]:
        severity = "WARNING"
    else:
        severity = "LOW"
        
    raw_status = str(event.get("event_status", "")).lower()
    if raw_status in ["blocked", "failed"]:
        status = "RESOLVED"
    else:
        status = "UNRESOLVED"
        
    is_high_risk = event.get("is_high_risk")
    if isinstance(is_high_risk, str):
        is_high_risk_bool = is_high_risk.lower() == "true"
    else:
        is_high_risk_bool = bool(is_high_risk)
        
    return {
        "id": numeric_id,
        "time": time_str,
        "timestamp": timestamp_str,
        "name": event.get("event_type", "Unknown Event"),
        "event_type": event.get("event_type", "Unknown Event"),
        "source": event.get("username", "System"),
        "source_ip": event.get("source_ip", ""),
        "target": event.get("asset_name", ""),
        "destination_ip": event.get("destination_ip", ""),
        "severity": severity,
        "status": status,
        "is_high_risk": is_high_risk_bool
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
    mapped_events = [map_event_to_frontend(evt) for evt in raw_events]
    return jsonify(mapped_events)
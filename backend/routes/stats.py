from flask import Blueprint, jsonify
from db import get_events_data

stats_bp = Blueprint("stats", __name__)

@stats_bp.route("/stats", methods=["GET"])
def get_stats():
    events = get_events_data()
    
    total_events = len(events)
    critical_threats = sum(1 for e in events if str(e.get("severity", "")).lower() == "critical")
    high_severity_alerts = sum(1 for e in events if str(e.get("severity", "")).lower() == "high")
    vulnerabilities = sum(1 for e in events if e.get("vulnerability_id") not in [None, "None", ""])
    active_incidents = sum(1 for e in events if str(e.get("event_status", "")).lower() not in ["blocked", "failed"])
    
    return jsonify({
        "totalEvents": total_events,
        "criticalThreats": critical_threats,
        "highSeverityAlerts": high_severity_alerts,
        "vulnerabilities": vulnerabilities,
        "activeIncidents": active_incidents
    })
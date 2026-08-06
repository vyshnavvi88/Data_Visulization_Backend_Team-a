from flask import Blueprint, jsonify
from db import get_events_data
from routes.events import map_event_to_frontend

threats_bp = Blueprint("threats", __name__)

@threats_bp.route("/threats", methods=["GET"])
def get_threats():
    events = get_events_data()
    # Unresolved events are those where event_status is not "Blocked" or "Failed" (case-insensitive)
    unresolved_events = [e for e in events if str(e.get("event_status", "")).lower() not in ["blocked", "failed"]]
    mapped_threats = [map_event_to_frontend(evt) for evt in unresolved_events]
    return jsonify(mapped_threats)
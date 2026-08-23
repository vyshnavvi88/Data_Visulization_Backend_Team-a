from flask import Blueprint, jsonify
from db import get_events_data, load_predictions
from routes.events import map_event_to_frontend

threats_bp = Blueprint("threats", __name__)

@threats_bp.route("/threats", methods=["GET"])
def get_threats():
    events = get_events_data()
    unresolved_events = [e for e in events if str(e.get("event_status", "")).lower() not in ["blocked", "failed"]]
    preds = load_predictions()
    mapped_threats = [map_event_to_frontend(evt, preds) for evt in unresolved_events]
    return jsonify(mapped_threats)
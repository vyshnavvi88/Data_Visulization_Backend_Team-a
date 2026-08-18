from flask import Blueprint, jsonify, request
from db import get_events_data, get_events_collection

threats_bp = Blueprint("threats", __name__)


# --------------------------------------------------
# GET /threats
# Groups Security_db.processed_events by event_type and returns
# counts sorted highest first.
#
# Supports optional filter:
#   GET /threats?severity=Critical
# --------------------------------------------------

@threats_bp.route("/threats", methods=["GET"])
def get_threats():

    severity_filter = request.args.get("severity")   # e.g. "Critical"

    collection = get_events_collection()

    # ---- MongoDB aggregation path ----------------------------------------
    if collection is not None:
        pipeline = []

        # Optional severity pre-filter
        if severity_filter:
            pipeline.append({"$match": {"severity": severity_filter}})

        pipeline += [
            {
                "$group": {
                    "_id": "$event_type",
                    "count": {"$sum": 1}
                }
            },
            {"$sort": {"count": -1}},
            {
                "$project": {
                    "_id": 0,
                    "event_type": "$_id",
                    "count": 1
                }
            }
        ]

        result = list(collection.aggregate(pipeline))
        return jsonify(result)

    # ---- CSV fallback path -----------------------------------------------
    events = get_events_data()

    if severity_filter:
        events = [e for e in events if str(e.get("severity", "")).lower() == severity_filter.lower()]

    counts = {}
    for e in events:
        et = e.get("event_type", "Unknown")
        counts[et] = counts.get(et, 0) + 1

    result = [{"event_type": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: x[1], reverse=True)]
    return jsonify(result)
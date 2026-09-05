from flask import Blueprint, jsonify
from db import get_events_data, get_events_collection

stats_bp = Blueprint("stats", __name__)


# --------------------------------------------------
# GET /stats
# Returns aggregate statistics from Security_db.processed_events
# --------------------------------------------------

@stats_bp.route("/stats", methods=["GET"])
def get_stats():

    collection = get_events_collection()

    # ---- MongoDB aggregation path ----------------------------------------
    if collection is not None:
        pipeline = [
            {
                "$group": {
                    "_id": None,
                    "total_events": {"$sum": 1},
                    "critical": {
                        "$sum": {
                            "$cond": [
                                {"$eq": [{"$toLower": "$severity"}, "critical"]},
                                1, 0
                            ]
                        }
                    },
                    "high": {
                        "$sum": {
                            "$cond": [
                                {"$eq": [{"$toLower": "$severity"}, "high"]},
                                1, 0
                            ]
                        }
                    },
                    "medium": {
                        "$sum": {
                            "$cond": [
                                {"$eq": [{"$toLower": "$severity"}, "medium"]},
                                1, 0
                            ]
                        }
                    },
                    "low": {
                        "$sum": {
                            "$cond": [
                                {"$eq": [{"$toLower": "$severity"}, "low"]},
                                1, 0
                            ]
                        }
                    },
                    # processed_events uses "status" field (not "event_status")
                    "vulnerabilities": {
                        "$sum": {
                            "$cond": [
                                {"$and": [
                                    {"$ne": ["$vulnerability_id", None]},
                                    {"$ne": ["$vulnerability_id", ""]},
                                    {"$ne": ["$vulnerability_id", "None"]}
                                ]},
                                1, 0
                            ]
                        }
                    },
                    "active_incidents": {
                        "$sum": {
                            "$cond": [
                                {"$not": {"$in": [
                                    {"$toLower": {"$ifNull": ["$status", ""]}},
                                    ["blocked", "failed"]
                                ]}},
                                1, 0
                            ]
                        }
                    }
                }
            }
        ]
        result = list(collection.aggregate(pipeline))
        if result:
            r = result[0]
            return jsonify({
                "totalEvents":        r.get("total_events", 0),
                "criticalThreats":    r.get("critical", 0),
                "highSeverityAlerts": r.get("high", 0),
                "mediumEvents":       r.get("medium", 0),
                "lowEvents":          r.get("low", 0),
                "vulnerabilities":    r.get("vulnerabilities", 0),
                "activeIncidents":    r.get("active_incidents", 0)
            })

    # ---- CSV fallback path -----------------------------------------------
    events = get_events_data()

    total_events      = len(events)
    critical_threats  = sum(1 for e in events if str(e.get("severity", "")).lower() == "critical")
    high_severity     = sum(1 for e in events if str(e.get("severity", "")).lower() == "high")
    medium_events     = sum(1 for e in events if str(e.get("severity", "")).lower() == "medium")
    low_events        = sum(1 for e in events if str(e.get("severity", "")).lower() == "low")
    vulnerabilities   = sum(1 for e in events if e.get("vulnerability_id") not in [None, "None", ""])
    # processed_events has a "status" field
    active_incidents  = sum(
        1 for e in events
        if str(e.get("status", e.get("event_status", ""))).lower() not in ["blocked", "failed"]
    )

    return jsonify({
        "totalEvents":        total_events,
        "criticalThreats":    critical_threats,
        "highSeverityAlerts": high_severity,
        "mediumEvents":       medium_events,
        "lowEvents":          low_events,
        "vulnerabilities":    vulnerabilities,
        "activeIncidents":    active_incidents
    })
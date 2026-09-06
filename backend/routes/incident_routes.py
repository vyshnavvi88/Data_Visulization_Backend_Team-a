"""
incident_routes.py
------------------
M3 Incident Management APIs

GET  /api/v1/incidents                    - All incidents
GET  /api/v1/incidents/<incident_id>      - Single incident
GET  /api/v1/attack-chains                - Correlated event groups
GET  /api/v1/recommendations/<incident_id>- Recommendations for incident
"""

import os
import pandas as pd
from flask import Blueprint, jsonify, request
from db import get_incidents_collection

incident_bp = Blueprint("incidents", __name__)

# --------------------------------------------------
# Data fallback path (CSV) if MongoDB unavailable
# --------------------------------------------------
_INCIDENTS_CSV = os.path.join(
    os.path.dirname(__file__), "..", "data", "processed", "incidents.csv"
)
_CORR_CSV = os.path.join(
    os.path.dirname(__file__), "..", "data", "processed", "correlated_events.csv"
)


def _get_all_incidents():
    """Returns list of incident dicts from MongoDB or CSV fallback."""
    col = get_incidents_collection()

    if col is not None:
        try:
            incidents = list(col.find({}, {"_id": 0}))
            if incidents:
                return incidents
        except Exception:
            pass

    # CSV fallback
    if os.path.exists(_INCIDENTS_CSV):
        df = pd.read_csv(_INCIDENTS_CSV).fillna("")
        return df.to_dict(orient="records")

    return []


# --------------------------------------------------
# GET /api/v1/incidents
# --------------------------------------------------

@incident_bp.route("/incidents", methods=["GET"])
def get_incidents():
    """
    Returns all incidents sorted by priority (Critical first).

    Query params:
      ?priority=Critical      filter by priority label
      ?status=Open            filter by status
      ?limit=50               max records (default 100)
      ?offset=0               pagination offset
    """
    priority_filter = request.args.get("priority")
    status_filter   = request.args.get("status")
    limit  = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))

    col = get_incidents_collection()

    if col is not None:
        try:
            query = {}
            if priority_filter:
                query["priority"] = {"$regex": priority_filter, "$options": "i"}
            if status_filter:
                query["status"] = {"$regex": status_filter, "$options": "i"}

            total = col.count_documents(query)
            incidents = list(
                col.find(query, {"_id": 0})
                   .sort("priority_rank", 1)
                   .skip(offset)
                   .limit(limit)
            )
            return jsonify({"total": total, "offset": offset, "limit": limit, "incidents": incidents})
        except Exception as e:
            pass  # fall through to CSV

    # CSV fallback
    if os.path.exists(_INCIDENTS_CSV):
        df = pd.read_csv(_INCIDENTS_CSV).fillna("")
        if priority_filter:
            df = df[df["priority"].str.lower() == priority_filter.lower()]
        if status_filter:
            df = df[df["status"].str.lower() == status_filter.lower()]
        df = df.sort_values("priority_rank")
        total = len(df)
        page  = df.iloc[offset: offset + limit].to_dict(orient="records")
        return jsonify({"total": total, "offset": offset, "limit": limit, "incidents": page})

    return jsonify({"error": "Incidents data not available"}), 503


# --------------------------------------------------
# GET /api/v1/incidents/<incident_id>
# --------------------------------------------------

@incident_bp.route("/incidents/<incident_id>", methods=["GET"])
def get_incident(incident_id):
    """
    Returns a single incident by incident_id (e.g. INC-0001).
    """
    col = get_incidents_collection()

    if col is not None:
        try:
            inc = col.find_one({"incident_id": incident_id}, {"_id": 0})
            if inc:
                return jsonify(inc)
        except Exception:
            pass

    # CSV fallback
    if os.path.exists(_INCIDENTS_CSV):
        df = pd.read_csv(_INCIDENTS_CSV).fillna("")
        match = df[df["incident_id"] == incident_id]
        if not match.empty:
            return jsonify(match.iloc[0].to_dict())

    return jsonify({"error": f"Incident {incident_id} not found"}), 404


# --------------------------------------------------
# GET /api/v1/attack-chains
# --------------------------------------------------

@incident_bp.route("/attack-chains", methods=["GET"])
def get_attack_chains():
    """
    Returns correlated event groups (attack chains).

    Each chain includes:
      - correlation_id
      - event_count
      - event_ids
      - highest risk_score
      - threat types involved
      - time span (first → last event)

    Query params:
      ?min_events=2    minimum events in chain (default 2)
      ?limit=50
    """
    min_events = int(request.args.get("min_events", 2))
    limit      = int(request.args.get("limit", 50))

    if not os.path.exists(_CORR_CSV):
        return jsonify({"error": "Correlation data not available"}), 503

    df = pd.read_csv(_CORR_CSV).fillna("")

    # Filter correlated only
    correlated = df[df["is_correlated"].apply(
        lambda x: str(x).lower() in ("true", "1")
    )]

    chains = []
    for corr_id, group in correlated.groupby("correlation_id"):
        if len(group) < min_events:
            continue

        group_sorted = group.sort_values("timestamp")

        chain = {
            "correlation_id":   corr_id,
            "event_count":      len(group),
            "event_ids":        group["event_id"].tolist(),
            "threat_types":     group["event_type"].unique().tolist(),
            "max_risk_score":   round(float(group["risk_score"].max()), 2),
            "risk_class":       group.loc[group["risk_score"].idxmax(), "risk_class"],
            "first_event_time": str(group_sorted["timestamp"].iloc[0]),
            "last_event_time":  str(group_sorted["timestamp"].iloc[-1]),
            "affected_users":   group["username"].unique().tolist(),
            "source_ips":       group["source_ip"].unique().tolist(),
            "asset_ids":        group["asset_id"].unique().tolist(),
            "mitre_techniques": group["mitre_id"].unique().tolist(),
            "tactics":          group["tactic"].unique().tolist(),
            "ioc_involved":     bool(group["ioc_match"].apply(
                lambda x: str(x).lower() in ("true", "1")
            ).any())
        }
        chains.append(chain)

    # Sort by max_risk_score desc
    chains.sort(key=lambda x: x["max_risk_score"], reverse=True)

    return jsonify({
        "total":  len(chains),
        "limit":  limit,
        "chains": chains[:limit]
    })


# --------------------------------------------------
# GET /api/v1/recommendations/<incident_id>
# --------------------------------------------------

@incident_bp.route("/recommendations/<incident_id>", methods=["GET"])
def get_recommendations_for_incident(incident_id):
    """
    Returns actionable recommendations for a given incident_id.
    """
    # Find the incident
    col = get_incidents_collection()
    incident = None

    if col is not None:
        try:
            incident = col.find_one({"incident_id": incident_id}, {"_id": 0})
        except Exception:
            pass

    if incident is None and os.path.exists(_INCIDENTS_CSV):
        df = pd.read_csv(_INCIDENTS_CSV).fillna("")
        match = df[df["incident_id"] == incident_id]
        if not match.empty:
            incident = match.iloc[0].to_dict()

    if incident is None:
        return jsonify({"error": f"Incident {incident_id} not found"}), 404

    # Get recommendations
    try:
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
        from risk.recommendations import get_recommendations

        # Handle case where recommendation is stored as string in CSV
        stored_recs = incident.get("recommendation", [])
        if isinstance(stored_recs, str):
            # Re-generate if stored as string
            recs = get_recommendations(
                event_type=str(incident.get("threat_type", "")),
                risk_class=str(incident.get("priority", "Medium")),
                ioc_match=str(incident.get("ioc_match", "false")).lower() in ("true", "1"),
                cvss_score=float(incident.get("cvss_score", 0) or 0)
            )
        else:
            recs = stored_recs
    except Exception as e:
        recs = ["Unable to generate recommendations: " + str(e)]

    return jsonify({
        "incident_id":  incident_id,
        "threat_type":  incident.get("threat_type", ""),
        "risk_score":   incident.get("risk_score", 0),
        "priority":     incident.get("priority", ""),
        "recommendation": recs
    })

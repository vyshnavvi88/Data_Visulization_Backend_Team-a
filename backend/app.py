import os
from flask import Flask, send_from_directory
from flask_cors import CORS

from routes.events import events_bp
from routes.stats import stats_bp
from routes.threats import threats_bp
from routes.auth import auth_bp
from routes.prediction_routes import prediction_bp
from routes.risk_routes import risk_bp
from routes.incident_routes import incident_bp
from db import get_connection_info

# Path to the frontend's dist folder (Naveen's integration)
frontend_dist_dir = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "Data_Visulization_Frontend_Team-a", "dist")
)

app = Flask(__name__, static_folder=frontend_dist_dir, static_url_path="")
app.secret_key = "security_project_secret_session_key"


# --------------------------------------------------
# CORS Configuration
# --------------------------------------------------

CORS(
    app,
    supports_credentials=True,
    origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173"
    ]
)


# --------------------------------------------------
# Milestone 1 APIs  (Security_db.processed_events)
# --------------------------------------------------

app.register_blueprint(events_bp,    url_prefix="/api")  # GET /api/events
app.register_blueprint(stats_bp,     url_prefix="/api")  # GET /api/stats
app.register_blueprint(threats_bp,   url_prefix="/api")  # GET /api/threats
app.register_blueprint(auth_bp)                          # POST /api/login  POST /api/signup


# --------------------------------------------------
# Milestone 2 Prediction APIs  (Security_db.prediction_results)
# --------------------------------------------------

app.register_blueprint(prediction_bp, url_prefix="/api")
# GET  /api/predictions
# GET  /api/predictions/<event_id>
# GET  /api/anomalies
# GET  /api/model-performance
# GET  /api/threat-summary
# POST /api/predict


# --------------------------------------------------
# Milestone 3 APIs  (Risk, Incidents, Attack Chains)
# --------------------------------------------------

app.register_blueprint(risk_bp,      url_prefix="/api/v1")
# GET  /api/v1/risk/summary
# GET  /api/v1/risk/high
# POST /api/v1/risk/calculate

app.register_blueprint(incident_bp,  url_prefix="/api/v1")
# GET  /api/v1/incidents
# GET  /api/v1/incidents/<incident_id>
# GET  /api/v1/attack-chains
# GET  /api/v1/recommendations/<incident_id>
# GET  /threat-summary
# POST /predict


# --------------------------------------------------
# API Health Check
# --------------------------------------------------

@app.route("/api")
def api_health():
    conn = get_connection_info()
    return {
        "Project":    "AI Threat Detection Dashboard",
        "Backend":    "Running",
        "Version":    "3.0",
        "Database":   conn["database"],
        "Connection": conn["source"],
        "Connected":  conn["connected"],
        "Milestone_1_2_Endpoints": [
            "GET  /api/events",
            "GET  /api/events?severity=Critical",
            "GET  /api/events?event_type=Brute Force",
            "GET  /api/stats",
            "GET  /api/threats",
            "GET  /api/threats?severity=Critical",
            "GET  /api/predictions",
            "GET  /api/predictions/<event_id>",
            "GET  /api/anomalies",
            "GET  /api/model-performance",
            "GET  /api/threat-summary",
            "POST /api/predict",
            "POST /api/login",
            "POST /api/signup"
        ],
        "Milestone_3_Endpoints": [
            "GET  /api/v1/risk/summary",
            "GET  /api/v1/risk/high",
            "GET  /api/v1/risk/high?risk_class=Critical",
            "GET  /api/v1/risk/high?limit=50&offset=0",
            "POST /api/v1/risk/calculate",
            "GET  /api/v1/incidents",
            "GET  /api/v1/incidents?priority=Critical",
            "GET  /api/v1/incidents?status=Open&limit=50&offset=0",
            "GET  /api/v1/incidents/<incident_id>",
            "GET  /api/v1/attack-chains",
            "GET  /api/v1/attack-chains?min_events=2&limit=50",
            "GET  /api/v1/recommendations/<incident_id>"
        ],
        "Docs": "See backend/README.md for full request/response details"
    }


# --------------------------------------------------
# Catch-all route — serve Vite built frontend files
# (Naveen's frontend integration)
# --------------------------------------------------

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve(path):
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        if os.path.exists(os.path.join(app.static_folder, "index.html")):
            return send_from_directory(app.static_folder, "index.html")
        # Fallback when frontend dist not built yet
        conn = get_connection_info()
        return {
            "Project":    "AI Threat Detection Dashboard",
            "Backend":    "Running",
            "Version":    "1.0",
            "Database":   conn["database"],
            "Connection": conn["source"],
            "Connected":  conn["connected"],
            "Note": "Frontend not built yet. Run 'npm run build' in the frontend repo."
        }


# --------------------------------------------------
# Start Flask Server
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False, host="0.0.0.0", port=5000)
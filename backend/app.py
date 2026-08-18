from flask import Flask
from flask_cors import CORS

from routes.events import events_bp
from routes.stats import stats_bp
from routes.threats import threats_bp
from routes.auth import auth_bp
from routes.prediction_routes import prediction_bp
from db import get_connection_info


app = Flask(__name__)

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

app.register_blueprint(events_bp)   # GET /events  (+ filters)  POST /events
app.register_blueprint(stats_bp)    # GET /stats
app.register_blueprint(threats_bp)  # GET /threats (+ filters)
app.register_blueprint(auth_bp)     # POST /api/login  POST /api/signup


# --------------------------------------------------
# Milestone 2 Prediction APIs  (Security_db.prediction_results)
# --------------------------------------------------

app.register_blueprint(prediction_bp)
# GET  /predictions
# GET  /predictions/<event_id>
# GET  /anomalies
# GET  /model-performance
# GET  /threat-summary
# POST /predict


# --------------------------------------------------
# Home / Health Check
# --------------------------------------------------

@app.route("/")
def home():
    conn = get_connection_info()
    return {
        "Project":    "AI Threat Detection Dashboard",
        "Backend":    "Running",
        "Version":    "1.0",
        "Database":   conn["database"],
        "Connection": conn["source"],       # "MongoDB Atlas" or "Local MongoDB Compass"
        "Connected":  conn["connected"],
        "Endpoints": [
            "GET  /events",
            "GET  /events?severity=Critical",
            "GET  /events?event_type=Brute Force",
            "GET  /stats",
            "GET  /threats",
            "GET  /threats?severity=Critical",
            "GET  /predictions",
            "GET  /predictions/<event_id>",
            "GET  /anomalies",
            "GET  /model-performance",
            "GET  /threat-summary",
            "POST /predict",
            "POST /api/login",
            "POST /api/signup"
        ]
    }


# --------------------------------------------------
# Start Flask Server
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)
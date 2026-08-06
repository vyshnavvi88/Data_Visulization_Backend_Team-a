from flask import Flask
from flask_cors import CORS

from routes.events import events_bp
from routes.stats import stats_bp
from routes.threats import threats_bp
from routes.auth import auth_bp

app = Flask(__name__)
app.secret_key = "security_project_secret_session_key"

# Enable CORS with credentials support for localhost development
CORS(app, supports_credentials=True, origins=[
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173"
])

app.register_blueprint(events_bp)
app.register_blueprint(stats_bp)
app.register_blueprint(threats_bp)
app.register_blueprint(auth_bp)

@app.route("/")
def home():

    return {
        "Project": "AI Threat Detection Dashboard",
        "Backend": "Running",
        "Version": "1.0"
    }

if __name__ == "__main__":
    app.run(debug=True)
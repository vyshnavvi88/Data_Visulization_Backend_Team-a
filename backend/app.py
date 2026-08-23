import os
from flask import Flask, send_from_directory
from flask_cors import CORS

from routes.events import events_bp
from routes.stats import stats_bp
from routes.threats import threats_bp
from routes.auth import auth_bp

# Path to the frontend's dist folder
frontend_dist_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "Data_Visulization_Frontend_Team-a", "dist"))

app = Flask(__name__, static_folder=frontend_dist_dir, static_url_path="")
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

# Catch-all route to serve Vite built frontend files
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve(path):
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, "index.html")

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False, host="0.0.0.0", port=5000)
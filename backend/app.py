from flask import Flask

from routes.events import events_bp
from routes.stats import stats_bp
from routes.threats import threats_bp

app = Flask(__name__)

app.register_blueprint(events_bp)
app.register_blueprint(stats_bp)
app.register_blueprint(threats_bp)

@app.route("/")
def home():

    return {
        "Project": "AI Threat Detection Dashboard",
        "Backend": "Running",
        "Version": "1.0"
    }

if __name__ == "__main__":
    app.run(debug=True)
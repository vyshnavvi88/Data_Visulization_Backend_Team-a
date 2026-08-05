from flask import Blueprint, jsonify
from pymongo import MongoClient

stats_bp = Blueprint("stats", __name__)

client = MongoClient("mongodb://localhost:27017/")
db = client["security_project"]
collection = db["events"]

@stats_bp.route("/stats", methods=["GET"])
def get_stats():
    return jsonify({
        "total_events": 5000,
        "critical_events": 50,
        "high_events": 120
    })
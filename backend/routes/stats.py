from flask import Blueprint, jsonify
from pymongo import MongoClient

stats_bp = Blueprint("stats", __name__)

client = MongoClient("mongodb://localhost:27017/")
db = client["security_project"]
collection = db["events"]

@stats_bp.route("/stats", methods=["GET"])
def get_stats():

    total = collection.count_documents({})
    critical = collection.count_documents({"severity": "Critical"})
    high = collection.count_documents({"severity": "High"})

    return jsonify({
        "total_events": total,
        "critical_events": critical,
        "high_events": high
    })
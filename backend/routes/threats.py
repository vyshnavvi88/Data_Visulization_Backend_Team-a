from flask import Blueprint, jsonify
from pymongo import MongoClient

threats_bp = Blueprint("threats", __name__)

client = MongoClient("mongodb://localhost:27017/")
db = client["security_project"]
collection = db["events"]

@threats_bp.route("/threats", methods=["GET"])
def get_threats():

    pipeline = [
        {"$group": {"_id": "$event_type", "count": {"$sum": 1}}}
    ]

    result = list(collection.aggregate(pipeline))

    output = []
    for r in result:
        output.append({
            "event_type": r["_id"],
            "count": r["count"]
        })

    return jsonify(output)
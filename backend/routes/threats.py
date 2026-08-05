from flask import Blueprint, jsonify
from pymongo import MongoClient

threats_bp = Blueprint("threats", __name__)

client = MongoClient("mongodb://localhost:27017/")
db = client["security_project"]
collection = db["events"]

@threats_bp.route("/threats", methods=["GET"])
def get_threats():
    return jsonify([
        {
            "event_type": "Brute Force",
            "count": 25
        }
    ])
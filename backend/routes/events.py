from flask import Blueprint, jsonify
from pymongo import MongoClient

events_bp = Blueprint("events", __name__)

client = MongoClient("mongodb://localhost:27017/")
db = client["security_project"]
collection = db["events"]

@events_bp.route("/events", methods=["GET"])
def get_events():
    data = list(collection.find({}, {"_id": 0}))
    return jsonify(data)
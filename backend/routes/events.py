from flask import Blueprint, jsonify
from pymongo import MongoClient

events_bp = Blueprint("events", __name__)

client = MongoClient("mongodb://localhost:27017/")
db = client["security_project"]
collection = db["events"]

from flask import request

@events_bp.route("/events", methods=["GET", "POST"])
def manage_events():
    if request.method == "POST":
        data = request.json
        if data:
            collection.insert_one(data)
            # Remove the ObjectId before returning to avoid JSON serialization error
            data.pop("_id", None)
            return jsonify({"message": "Event added successfully", "event": data}), 201
        return jsonify({"error": "No data provided"}), 400

    # GET request handling
    data = list(collection.find({}, {"_id": 0}))
    return jsonify(data)
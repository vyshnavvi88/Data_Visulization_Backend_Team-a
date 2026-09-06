"""
upload_to_mongo.py
------------------
Loads Security_db.processed_events.csv into MongoDB Security_db.processed_events.

- Uses MONGO_URI env-var for MongoDB Atlas when available.
- Falls back to local MongoDB Compass (mongodb://localhost:27017/).
- Uses upsert by event_id to avoid creating duplicate event records on re-run.
- Never touches Security_db.prediction_results.

Usage:
    python backend/upload_to_mongo.py
"""

import os
import pandas as pd
from pymongo import MongoClient, UpdateOne
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

# --------------------------------------------------
# Config
# --------------------------------------------------

DATABASE_NAME      = "Security_db"
COLLECTION_NAME    = "processed_events"

# Path relative to project root (run from project root)
CSV_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "data", "processed",
    "Security_db.processed_events.csv"
)

# --------------------------------------------------
# Connect to MongoDB
# --------------------------------------------------

uri = os.getenv("MONGO_URI")
if uri:
    print("Connecting to MongoDB Atlas …")
    client = MongoClient(uri, serverSelectionTimeoutMS=10000)
else:
    print("Connecting to Local MongoDB Compass (mongodb://localhost:27017/) …")
    client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)

try:
    client.admin.command("ping")
    print("MongoDB connection successful.")
except (ConnectionFailure, ServerSelectionTimeoutError) as exc:
    print(f"ERROR: Cannot connect to MongoDB: {exc}")
    raise SystemExit(1)

db         = client[DATABASE_NAME]
collection = db[COLLECTION_NAME]

# --------------------------------------------------
# Load CSV
# --------------------------------------------------

if not os.path.exists(CSV_PATH):
    print(f"ERROR: CSV not found at {CSV_PATH}")
    raise SystemExit(1)

df = pd.read_csv(CSV_PATH)
# Replace NaN with None so MongoDB receives null instead of NaN
df = df.where(pd.notnull(df), None)
records = df.to_dict(orient="records")

print(f"\nCSV loaded  : {len(records)} rows")

# --------------------------------------------------
# Upsert by event_id (safe to re-run; no duplicate events)
# --------------------------------------------------

if not records:
    print("No records to insert.")
else:
    operations = [
        UpdateOne(
            {"event_id": r.get("event_id")},  # filter
            {"$setOnInsert": r},               # only set on first insert
            upsert=True
        )
        for r in records
    ]

    result = collection.bulk_write(operations, ordered=False)
    inserted  = result.upserted_count
    matched   = result.matched_count

    print(f"Records inserted (new): {inserted}")
    print(f"Records already existed: {matched}")

# --------------------------------------------------
# Summary
# --------------------------------------------------

total_docs = collection.count_documents({})
print(f"\n--- Summary ---")
print(f"  Database  : {DATABASE_NAME}")
print(f"  Collection: {COLLECTION_NAME}")
print(f"  Total documents in collection: {total_docs}")

client.close()
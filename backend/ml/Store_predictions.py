"""
Store_predictions.py
--------------------
Loads prediction_results.csv into MongoDB Security_db.prediction_results.

- Uses MONGO_URI env-var for Atlas when available, otherwise local Compass.
- Skips upload if Security_db.prediction_results already has records.
- NEVER deletes or overwrites existing prediction records.
"""

import pandas as pd
from pymongo import MongoClient
import os

# --------------------------------------------------
# 1. Load prediction results CSV
# --------------------------------------------------

CSV_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),   # backend/ml/
    "..", "data", "processed",
    "prediction_results.csv"
)
CSV_PATH = os.path.normpath(CSV_PATH)

df = pd.read_csv(CSV_PATH)
print("Prediction records loaded:", len(df))


# --------------------------------------------------
# 2. Connect to MongoDB (Atlas or local Compass)
# --------------------------------------------------

uri = os.getenv("MONGO_URI")

if uri:
    print("Using MongoDB Atlas")
    client = MongoClient(uri, serverSelectionTimeoutMS=10000)
else:
    print("Using Local MongoDB Compass (mongodb://localhost:27017/)")
    client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)


# --------------------------------------------------
# 3. Verify connection
# --------------------------------------------------

client.admin.command("ping")
print("MongoDB Connected Successfully")


# --------------------------------------------------
# 4. Select Security_db.prediction_results
# --------------------------------------------------

db         = client["Security_db"]          # <-- correct database
collection = db["prediction_results"]


# --------------------------------------------------
# 5. Skip if already populated (protect existing records)
# --------------------------------------------------

existing_count = collection.count_documents({})
print(f"Existing records in Security_db.prediction_results: {existing_count}")

if existing_count >= len(df):
    print(f"Collection already has {existing_count} records. Skipping upload to avoid duplicates.")
else:
    # Convert DataFrame to list of dicts
    # Replace NaN with None so MongoDB gets null
    df = df.where(pd.notnull(df), None)
    records = df.to_dict("records")

    # Clear only if less than expected (partial state)
    if existing_count > 0:
        print(f"Partial data detected ({existing_count} records). Clearing and reinserting.")
        collection.delete_many({})

    collection.insert_many(records)
    print(f"Prediction results stored successfully: {len(records)} records inserted.")


# --------------------------------------------------
# 6. Summary
# --------------------------------------------------

print("\n--- Summary ---")
print("Database   :", db.name)
print("Collection :", collection.name)
print("Documents  :", collection.count_documents({}))

client.close()
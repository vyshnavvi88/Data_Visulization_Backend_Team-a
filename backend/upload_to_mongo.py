import pandas as pd
from pymongo import MongoClient

# Connect MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["security_project"]
collection = db["events"]

# Check if collection already has documents to prevent duplicates
count = collection.count_documents({})
if count > 0:
    print(f"Collection 'events' already contains {count} documents. Skipping upload.")
else:
    # Load CSV
    df = pd.read_csv("backend/data/processed/final_security_dataset.csv")

    # Convert DataFrame → dictionary
    data = df.to_dict(orient="records")

    # Insert into MongoDB
    collection.insert_many(data)
    print(f"Successfully uploaded {len(data)} events to MongoDB.")
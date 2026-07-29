import pandas as pd
from pymongo import MongoClient

# Connect MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["cybersecurity_db"]
collection = db["events"]

# Load CSV
df = pd.read_csv("backend/data/processed/final_security_dataset.csv")

# Convert DataFrame → dictionary
data = df.to_dict(orient="records")

# Insert into MongoDB
collection.insert_many(data)
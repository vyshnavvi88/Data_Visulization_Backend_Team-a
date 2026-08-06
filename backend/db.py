import os
import json
import pandas as pd
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

_client = None
_db = None
_events_collection = None
_users_collection = None
_fallback_mode = None  # None = not determined yet, True = using fallback, False = using MongoDB

FALLBACK_USERS_FILE = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "users_fallback.json"))

def init_default_admin():
    from werkzeug.security import generate_password_hash
    hashed_pwd = generate_password_hash("admin123")
    
    # 1. MongoDB check
    if _users_collection is not None:
        try:
            if _users_collection.count_documents({"username": "admin"}) == 0:
                admin_user = {
                    "username": "admin",
                    "email": "admin@threatdetect.local",
                    "password": hashed_pwd
                }
                _users_collection.insert_one(admin_user)
                print("Default admin user created in MongoDB.")
        except Exception as e:
            print("Failed to initialize default admin in MongoDB:", e)
            
    # 2. JSON Fallback check
    users = load_fallback_users()
    if not users or "admin" not in users:
        admin_user = {
            "username": "admin",
            "email": "admin@threatdetect.local",
            "password": hashed_pwd
        }
        users["admin"] = admin_user
        save_fallback_users(users)
        print("Default admin user created in fallback JSON.")

def get_db():
    global _client, _db, _events_collection, _users_collection, _fallback_mode
    
    # If fallback mode status is already determined, return the MongoDB handles if active
    if _fallback_mode is False:
        return _events_collection, _users_collection
        
    if _fallback_mode is True:
        return None, None
        
    # Check connection
    try:
        # 1-second timeout to check fast
        _client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=1000)
        _client.admin.command('ping')
        _db = _client["security_project"]
        _events_collection = _db["events"]
        _users_collection = _db["users"]
        _fallback_mode = False
        print("Successfully connected to MongoDB.")
        init_default_admin()
        return _events_collection, _users_collection
    except (ConnectionFailure, ServerSelectionTimeoutError):
        print("Could not connect to MongoDB. Activating local file fallback mode.")
        _fallback_mode = True
        init_default_admin()
        return None, None

def get_events_data():
    events_col, _ = get_db()
    if events_col is not None:
        # Make a copy of events from DB to avoid mutating them in-memory
        return list(events_col.find())
    
    # CSV Fallback logic
    csv_path = os.path.join(os.path.dirname(__file__), "data", "processed", "final_security_dataset.csv")
    if os.path.exists(csv_path):
        try:
            df = pd.read_csv(csv_path)
            # Replace NaNs/Nulls with empty strings to avoid JSON errors
            df = df.fillna("")
            return df.to_dict(orient="records")
        except Exception as e:
            print("Error loading CSV:", e)
    return []

def insert_event_data(event_data):
    events_col, _ = get_db()
    if events_col is not None:
        events_col.insert_one(event_data)
        return True
        
    # CSV Fallback logic: append to CSV
    csv_path = os.path.join(os.path.dirname(__file__), "data", "processed", "final_security_dataset.csv")
    if os.path.exists(csv_path):
        try:
            df = pd.read_csv(csv_path)
            event_cleaned = {k: v for k, v in event_data.items() if k != "_id"}
            new_df = pd.DataFrame([event_cleaned])
            df = pd.concat([df, new_df], ignore_index=True)
            df.to_csv(csv_path, index=False)
            return True
        except Exception as e:
            print("Failed to append to CSV:", e)
    return False

def get_user_by_username_or_email(identity):
    _, users_col = get_db()
    if users_col is not None:
        return users_col.find_one({"$or": [{"username": identity}, {"email": identity}]})
        
    # Local JSON fallback logic
    users = load_fallback_users()
    for user in users.values():
        if user["username"] == identity or user["email"] == identity:
            return user
    return None

def create_user(username, email, hashed_password):
    _, users_col = get_db()
    if users_col is not None:
        if users_col.find_one({"username": username}) or users_col.find_one({"email": email}):
            return False, "Username or email already exists."
        user = {
            "username": username,
            "email": email,
            "password": hashed_password
        }
        users_col.insert_one(user)
        return True, "User registered successfully."
        
    # Local JSON fallback logic
    users = load_fallback_users()
    for user in users.values():
        if user["username"] == username or user["email"] == email:
            return False, "Username or email already exists."
            
    new_user = {
        "username": username,
        "email": email,
        "password": hashed_password
    }
    users[username] = new_user
    save_fallback_users(users)
    return True, "User registered successfully."

def load_fallback_users():
    if os.path.exists(FALLBACK_USERS_FILE):
        try:
            with open(FALLBACK_USERS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_fallback_users(users):
    os.makedirs(os.path.dirname(FALLBACK_USERS_FILE), exist_ok=True)
    try:
        with open(FALLBACK_USERS_FILE, "w") as f:
            json.dump(users, f, indent=4)
    except Exception as e:
        print("Failed to save fallback users:", e)

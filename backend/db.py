import os
import json
import pandas as pd
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

# --------------------------------------------------
# Database / Collection Constants
# --------------------------------------------------

DATABASE_NAME       = "Security_db"
EVENTS_COLLECTION   = "processed_events"
PREDICT_COLLECTION  = "prediction_results"
USERS_COLLECTION    = "users"

# --------------------------------------------------
# Module-level singletons
# --------------------------------------------------

_client                 = None
_db                     = None
_events_collection      = None
_users_collection       = None
_predictions_collection = None
_fallback_mode          = None  # None = not determined, False = MongoDB OK, True = fallback
_connection_source      = "Not connected"  # "MongoDB Atlas" | "Local MongoDB Compass" | "CSV Fallback"

FALLBACK_USERS_FILE = os.path.abspath(
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "users_fallback.json")
)

# Primary CSV fallback source for events
_CSV_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "data", "processed",
        "Security_db.processed_events.csv"
    )
)


# --------------------------------------------------
# Default admin initialisation
# --------------------------------------------------

def init_default_admin():
    from werkzeug.security import generate_password_hash
    hashed_pwd = generate_password_hash("admin123")

    # 1. MongoDB check
    if _users_collection is not None:
        try:
            if _users_collection.count_documents({"username": "admin"}) == 0:
                admin_user = {
                    "username": "admin",
                    "email":    "admin@threatdetect.local",
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
            "email":    "admin@threatdetect.local",
            "password": hashed_pwd
        }
        users["admin"] = admin_user
        save_fallback_users(users)
        print("Default admin user created in fallback JSON.")



# --------------------------------------------------
# Connection info helper
# --------------------------------------------------

def get_connection_info():
    """Returns a dict describing the active MongoDB connection."""
    global _connection_source, _fallback_mode, _db, _events_collection, _predictions_collection, _users_collection
    if _fallback_mode is None:
        get_db()   # trigger connection
    return {
        "source":   _connection_source,
        "database": DATABASE_NAME if _fallback_mode is False else "N/A (CSV Fallback)",
        "connected": _fallback_mode is False
    }


# --------------------------------------------------
# Primary connection helper
# --------------------------------------------------

def get_db():
    """
    Returns (events_collection, users_collection).

    Database  : Security_db
    Collections:
        processed_events    – security event data  (was: events in security_project)
        prediction_results  – ML prediction results
        users               – authentication users

    Connects to MongoDB Atlas when MONGO_URI env-var is present,
    otherwise tries local MongoDB Compass at mongodb://localhost:27017/.
    Falls back gracefully to (None, None) on failure.
    """
    global _client, _db
    global _events_collection, _users_collection, _predictions_collection
    global _fallback_mode

    if _fallback_mode is False:
        return _events_collection, _users_collection
    if _fallback_mode is True:
        return None, None

    try:
        uri = os.getenv("MONGO_URI")
        global _connection_source

        # ---- Try Atlas first if MONGO_URI is set ----
        if uri:
            try:
                print("Trying MongoDB Atlas …")
                _client = MongoClient(uri, serverSelectionTimeoutMS=5000)
                _client.admin.command("ping")
                _connection_source = "MongoDB Atlas"
                print("Connected to MongoDB Atlas.")
            except Exception as atlas_err:
                print(f"Atlas unavailable ({type(atlas_err).__name__}). Falling back to local Compass …")
                _client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=3000)
                _client.admin.command("ping")
                _connection_source = "Local MongoDB Compass"
                print("Connected to Local MongoDB Compass.")
        else:
            print("Using Local MongoDB Compass (mongodb://localhost:27017/)")
            _client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=3000)
            _client.admin.command("ping")
            _connection_source = "Local MongoDB Compass"

        _db                     = _client[DATABASE_NAME]
        _events_collection      = _db[EVENTS_COLLECTION]
        _users_collection       = _db[USERS_COLLECTION]
        _predictions_collection = _db[PREDICT_COLLECTION]

        _fallback_mode = False
        print(f"Successfully connected to MongoDB ({_connection_source}).")
        print(f"  Database   : {_db.name}")
        print(f"  Events     : {_events_collection.count_documents({})} documents  (collection: {EVENTS_COLLECTION})")
        print(f"  Users      : {_users_collection.count_documents({})} documents")
        print(f"  Predictions: {_predictions_collection.count_documents({})} documents")

        init_default_admin()
        return _events_collection, _users_collection

    except (ConnectionFailure, ServerSelectionTimeoutError) as exc:
        print(f"Could not connect to MongoDB ({exc}). Activating local file fallback mode.")
        _fallback_mode = True
        _connection_source = "CSV Fallback"
        init_default_admin()
        return None, None



# --------------------------------------------------
# Prediction collection accessor
# --------------------------------------------------

def get_predictions_collection():
    """Returns the prediction_results collection handle, or None if unavailable."""
    global _predictions_collection, _fallback_mode

    if _fallback_mode is None:
        get_db()

    if _fallback_mode is False:
        return _predictions_collection

    return None


# --------------------------------------------------
# Events collection accessor (for aggregation / direct queries)
# --------------------------------------------------

def get_events_collection():
    """
    Returns the processed_events collection handle for direct MongoDB operations
    (aggregation, filtered queries, etc.), or None if MongoDB is unavailable.
    """
    global _events_collection, _fallback_mode

    if _fallback_mode is None:
        get_db()

    if _fallback_mode is False:
        return _events_collection

    return None


# --------------------------------------------------
# Events data accessor (with CSV fallback)
# --------------------------------------------------

def get_events_data():
    """
    Returns a list of event dicts from Security_db.processed_events.
    Falls back to reading Security_db.processed_events.csv when MongoDB is
    unavailable.
    """
    events_col, _ = get_db()
    if events_col is not None:
        return list(events_col.find({}, {"_id": 0}))

    # CSV Fallback
    if os.path.exists(_CSV_PATH):
        try:
            df = pd.read_csv(_CSV_PATH)
            df = df.fillna("")
            return df.to_dict(orient="records")
        except Exception as e:
            print("Error loading CSV fallback:", e)
    return []


# --------------------------------------------------
# Event insert helper
# --------------------------------------------------

def insert_event_data(event_data):
    events_col, _ = get_db()
    if events_col is not None:
        events_col.insert_one(event_data)
        return True

    # CSV Fallback: append row
    if os.path.exists(_CSV_PATH):
        try:
            df = pd.read_csv(_CSV_PATH)
            event_cleaned = {k: v for k, v in event_data.items() if k != "_id"}
            new_df = pd.DataFrame([event_cleaned])
            df = pd.concat([df, new_df], ignore_index=True)
            df.to_csv(_CSV_PATH, index=False)
            return True
        except Exception as e:
            print("Failed to append to CSV:", e)
    return False


# --------------------------------------------------
# User helpers
# --------------------------------------------------

def get_user_by_username_or_email(identity):
    _, users_col = get_db()
    if users_col is not None:
        return users_col.find_one(
            {"$or": [{"username": identity}, {"email": identity}]}
        )

    # Local JSON fallback
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
            "email":    email,
            "password": hashed_password
        }
        users_col.insert_one(user)
        return True, "User registered successfully."

    # Local JSON fallback
    users = load_fallback_users()
    for user in users.values():
        if user["username"] == username or user["email"] == email:
            return False, "Username or email already exists."

    new_user = {
        "username": username,
        "email":    email,
        "password": hashed_password
    }
    users[username] = new_user
    save_fallback_users(users)
    return True, "User registered successfully."


# --------------------------------------------------
# JSON fallback file helpers
# --------------------------------------------------

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

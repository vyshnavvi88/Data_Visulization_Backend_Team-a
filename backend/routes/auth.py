from flask import Blueprint, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_user_by_username_or_email, create_user

auth_bp = Blueprint("auth", __name__)


def _verify_password(stored_password, provided_password):
    """Safely verifies password whether it is hashed or plaintext."""
    if not stored_password or not provided_password:
        return False
    if stored_password == provided_password:
        return True
    try:
        return check_password_hash(stored_password, provided_password)
    except Exception:
        return False


@auth_bp.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()
    
    if not username or not email or not password:
        return jsonify({"error": "Missing required fields (username, email, password)"}), 400
        
    # Hash password
    hashed_password = generate_password_hash(password)
    
    # Save user using helper
    success, message = create_user(username, email, hashed_password)
    if not success:
        return jsonify({"error": message}), 409
        
    return jsonify({"message": message}), 201


@auth_bp.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or request.form.to_dict() or {}
    if not data:
        return jsonify({"error": "No data provided"}), 400
        
    # Support 'identity', 'username', or 'email' sent from frontend forms
    identity = (
        data.get("identity") or 
        data.get("username") or 
        data.get("email") or 
        ""
    ).strip()
    
    password = (data.get("password") or "").strip()
    
    if not identity or not password:
        return jsonify({"error": "Missing username/email or password"}), 400
        
    # Find user using helper
    user = get_user_by_username_or_email(identity)
    
    if not user or not _verify_password(user.get("password", ""), password):
        return jsonify({"error": "Invalid username/email or password."}), 401
        
    # Set session
    session["username"] = user["username"]
    session["email"] = user["email"]
    
    return jsonify({
        "message": "Login successful",
        "username": user["username"],
        "email": user["email"]
    }), 200


@auth_bp.route("/api/me", methods=["GET"])
def current_user():
    username = session.get("username")
    email = session.get("email")
    if username:
        return jsonify({"authenticated": True, "username": username, "email": email}), 200
    return jsonify({"authenticated": False}), 200


@auth_bp.route("/api/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200


from flask import Blueprint, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_user_by_username_or_email, create_user

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    
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
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
        
    identity = data.get("identity")
    password = data.get("password")
    
    if not identity or not password:
        return jsonify({"error": "Missing identity or password"}), 400
        
    # Find user using helper
    user = get_user_by_username_or_email(identity)
    
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid username/email or password."}), 401
        
    # Set session
    session["username"] = user["username"]
    session["email"] = user["email"]
    
    return jsonify({
        "username": user["username"],
        "email": user["email"]
    }), 200

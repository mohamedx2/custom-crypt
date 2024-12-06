from flask import Flask, request, jsonify, make_response
import sqlite3
import jwt
import datetime
from functools import wraps
from hash import manual_hash
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this in production
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change this in production
jwt_manager = JWTManager(app)

DATABASE = "users.db"

# Initialize the database
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL, 
                salt TEXT NOT NULL
            )
        """)
        conn.commit()

# Register a new user
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Missing 'username' or 'password'"}), 400

    username = data["username"]
    password = data["password"]
    salt = f"{username}_salt"  # Use a unique salt per user

    # Hash the password
    hashed_password = manual_hash(password, salt)

    try:
        # Store the user in the database
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, hashed_password, salt)
                VALUES (?, ?, ?)
            """, (username, str(hashed_password), salt))  # Convert hash to string
            conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "User already exists"}), 400

    return jsonify({"message": f"User '{username}' registered successfully"}), 201

# Login route, generates JWT token
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Missing 'username' or 'password'"}), 400

    username = data["username"]
    password = data["password"]

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT hashed_password, salt FROM users WHERE username = ?
        """, (username,))
        result = cursor.fetchone()

    if not result:
        return jsonify({"error": "User not found"}), 404

    stored_hashed_password, stored_salt = result
    provided_hashed_password = manual_hash(password, stored_salt)

    if str(provided_hashed_password) != stored_hashed_password:
        return jsonify({"error": "Invalid username or password"}), 401

    # Create JWT token
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200

# Protected profile route that requires a valid JWT
@app.route("/profile", methods=["GET"])
@jwt_required()
def profile():
    current_user = get_jwt_identity()  # Get the username from the JWT
    return jsonify(message=f"Hello, {current_user}"), 200

# Initialize the database
init_db()

if __name__ == "__main__":
    app.run(debug=True)

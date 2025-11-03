from flask import Flask, render_template, jsonify, send_file, request
from werkzeug.security import check_password_hash, generate_password_hash
import os
import requests
import json
import random
import string
import secrets

app = Flask(__name__)
USER_DIR = "/var/www/users"
RUNNER_LIMIT = 1
CF_SECRET_KEY = "0x4AAAAAAB-oyZOuYUUuz-JjT6SN5-XXyeM"

if not os.path.exists(USER_DIR):
    os.makedirs(USER_DIR, exist_ok=True)

def generate_unique_userid():
    while True:
        length = random.randint(7, 15)
        user_id = ''.join(random.choices(string.digits, k=length))
        if not os.path.exists(f"{USER_DIR}/{user_id}.json"):
            return user_id

def generate_api_key():
    length = random.randint(20, 23)
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

@app.route('/sitemap.xml', methods=['GET'])
def sitemap():
    return send_file('sitemap.xml', mimetype='application/xml')

@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    cf_token = data.get("cf_token")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if not cf_token:
        return jsonify({"error": "CAPTCHA verification required"}), 400

    verify = requests.post(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data={
            "secret": CF_SECRET_KEY,
            "response": cf_token,
            "remoteip": request.remote_addr
        }
    )
    verify_result = verify.json()
    if not verify_result.get("success"):
        return jsonify({"error": "CAPTCHA verification failed"}), 400

    for file in os.listdir(USER_DIR):
        with open(os.path.join(USER_DIR, file), "r") as f:
            user_data = json.load(f)
            if user_data["username"] == username:
                return jsonify({"error": "Username already exists"}), 400

    user_id = generate_unique_userid()
    hashed_password = generate_password_hash(password)
    api_key = generate_api_key()
    session_token = secrets.token_hex(32)

    user_data = {
        "userID": user_id,
        "username": username,
        "password": hashed_password,
        "api_key": api_key,
        "session_token": session_token
    }

    with open(os.path.join(USER_DIR, f"{user_id}.json"), "w") as f:
        json.dump(user_data, f, indent=4)

    return jsonify({"userID": user_id, "sessionToken": session_token}), 201

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username_input = data.get("username")
    password_input = data.get("password")
    if not username_input or not password_input:
        return jsonify({"error": "Username/UserID and password required"}), 400

    for file in os.listdir(USER_DIR):
        with open(os.path.join(USER_DIR, file), "r") as f:
            user_data = json.load(f)
            if user_data["username"] == username_input or user_data["userID"] == username_input:
                if check_password_hash(user_data["password"], password_input):
                    user_data["session_token"] = secrets.token_hex(32)
                    with open(os.path.join(USER_DIR, file), "w") as fw:
                        json.dump(user_data, fw, indent=4)
                    return jsonify({
                        "userID": user_data["userID"],
                        "sessionToken": user_data["session_token"],
                        "api_key": user_data["api_key"]
                    }), 200
                else:
                    return jsonify({"error": "Invalid password"}), 401
    return jsonify({"error": "User not found"}), 404

@app.route("/api/logout", methods=["POST"])
def logout():
    data = request.json
    user_id = data.get("userID")
    session_token = data.get("sessionToken")
    if not user_id or not session_token:
        return jsonify({"error": "userID and sessionToken required"}), 400

    user_file = os.path.join(USER_DIR, f"{user_id}.json")
    if not os.path.exists(user_file):
        return jsonify({"error": "User not found"}), 404

    with open(user_file, "r") as f:
        user_data = json.load(f)

    if user_data.get("session_token") != session_token:
        return jsonify({"error": "Invalid sessionToken"}), 401

    user_data["session_token"] = secrets.token_hex(32)
    with open(user_file, "w") as f:
        json.dump(user_data, f, indent=4)

    return jsonify({"message": "Logged out successfully"}), 200


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/register")
def registerPAGE():
    return render_template("register.html")

@app.route("/login")
def loginPAGE():
    return render_template("login.html")

@app.route("/dash_test")
def dashTEST():
    return render_template("dash.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

from flask import Flask, render_template, jsonify, send_file
from werkzeug.security import generate_password_hash
import os
import json
import random
import string
import secrets

app = Flask(__name__)
USER_DIR = "/var/www/users"

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

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

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

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/dashboard")
def dasg():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

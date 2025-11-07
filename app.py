from flask import Flask, render_template, jsonify, send_file, request
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
import os
import requests
import json
import random
import string
import secrets
import html
import re

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
    creation_date = datetime.utcnow().isoformat() + "Z"

    user_data = {
        "userID": user_id,
        "username": username,
        "password": hashed_password,
        "api_key": api_key,
        "session_token": session_token,
        "creation_date": creation_date,
        "Posts": [],
        "Followers": 0,
        "Following": 0,
        "Follower_list": [],
        "Following_list": []
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


@app.route('/user/<user_identifier>')
def user_profile(user_identifier):
    if not re.match(r'^[a-zA-Z0-9_-]+$', user_identifier):
        return "Invalid user identifier", 400
    
    user_file_path = None
    user_data = None
    
    for filename in os.listdir(USER_DIR):
        if filename.endswith('.json') and filename[:-5] == user_identifier:
            user_file_path = os.path.join(USER_DIR, filename)
            break
        else:
            try:
                file_path = os.path.join(USER_DIR, filename)
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    if data.get('username') == user_identifier:
                        user_file_path = file_path
                        user_data = data
                        break
            except:
                continue
    
    if not user_file_path and not user_data:
        for filename in os.listdir(USER_DIR):
            if filename.endswith('.json'):
                try:
                    file_path = os.path.join(USER_DIR, filename)
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        if data.get('username') == user_identifier or data.get('userID') == user_identifier:
                            user_file_path = file_path
                            user_data = data
                            break
                except Exception as e:
                    continue
    
    if not user_data and user_file_path:
        try:
            with open(user_file_path, 'r') as f:
                user_data = json.load(f)
        except:
            return "User not found", 404
    
    if not user_data:
        return "User not found", 404
    
    creation_date = user_data.get('creation_date', '')
    if creation_date:
        try:
            if creation_date.endswith('Z'):
                creation_date = creation_date[:-1]
            dt = datetime.fromisoformat(creation_date)
            formatted_date = dt.strftime('%b %d, %Y')
        except ValueError:
            formatted_date = 'Unknown'
    else:
        formatted_date = 'Unknown'
    
    paste_count = len(user_data.get('Posts', []))
    following_count = user_data.get('Following', 0)
    followers_count = user_data.get('Followers', 0)
    
    posts = user_data.get('Posts', [])[:5]
    
    safe_posts = []
    for post in posts:
        if isinstance(post, dict):
            safe_post = {
                'title': html.escape(str(post.get('title', 'Untitled'))),
                'comments': html.escape(str(post.get('comments', 0))),
                'views': html.escape(str(post.get('views', 0))),
                'added': 'Unknown date'
            }
            
            added = post.get('added', '')
            if added and added != 'Unknown date':
                try:
                    if added.endswith('Z'):
                        added = added[:-1]
                    dt_post = datetime.fromisoformat(added)
                    safe_post['added'] = html.escape(dt_post.strftime('%b %d, %Y'))
                except ValueError:
                    safe_post['added'] = html.escape(str(added))
            
            safe_posts.append(safe_post)
    
    return render_template('profile_page.html',
                         username=html.escape(user_data.get('username', 'Unknown')),
                         user_id=html.escape(user_data.get('userID', 'Unknown')),
                         creation_date=html.escape(formatted_date),
                         paste_count=paste_count,
                         following_count=following_count,
                         followers_count=followers_count,
                         posts=safe_posts,
                         has_posts=len(posts) > 0)
    
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

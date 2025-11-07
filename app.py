from flask import Flask, render_template, jsonify, send_file, request
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
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
    for filename in os.listdir(USER_DIR):
        if filename.endswith('.json'):
            file_path = os.path.join(USER_DIR, filename)
            try:
                with open(file_path, 'r') as f:
                    user_data = json.load(f)
                    
                    if user_data.get('userID') == user_identifier or user_data.get('username') == user_identifier:
                        creation_date = user_data.get('creation_date', '')
                        if creation_date:
                            try:
                                if creation_date.endswith('Z'):
                                    creation_date = creation_date[:-1]
                                dt = datetime.fromisoformat(creation_date)
                                formatted_date = dt.strftime('%b %d, %Y')
                            except ValueError:
                                formatted_date = creation_date
                        else:
                            formatted_date = 'Unknown'
                        
                        paste_count = len(user_data.get('Posts', []))
                        
                        with open('templates/profile_page.html', 'r') as template_file:
                            html_content = template_file.read()
                        
                        html_content = html_content.replace('Rocioschoolfuck', user_data.get('username', 'Unknown'))
                        html_content = html_content.replace('595255', user_data.get('userID', 'Unknown'))
                        html_content = html_content.replace('Nov 1, 2025', formatted_date)
                        html_content = html_content.replace('"7"', f'"{paste_count}"')
                        html_content = html_content.replace('Showing 5 out of 7 pastes', f'Showing {min(5, paste_count)} out of {paste_count} pastes')
                        
                        following_count = user_data.get('Following', 0)
                        followers_count = user_data.get('Followers', 0)
                        html_content = html_content.replace('"follow-count">0<', f'"follow-count">{following_count}<')
                        html_content = html_content.replace('"follow-count">0</span>', f'"follow-count">{followers_count}</span>')
                        
                        posts_html = ''
                        posts = user_data.get('Posts', [])[:5]
                        
                        for post in posts:
                            if isinstance(post, dict):
                                title = post.get('title', 'Untitled')
                                comments = post.get('comments', 0)
                                views = post.get('views', 0)
                                added = post.get('added', 'Unknown date')
                                
                                if added and added != 'Unknown date':
                                    try:
                                        if added.endswith('Z'):
                                            added = added[:-1]
                                        dt_post = datetime.fromisoformat(added)
                                        added = dt_post.strftime('%b %d, %Y')
                                    except ValueError:
                                        pass
                                
                                posts_html += f'''
                                <tr class="paste-row">
                                    <td>{title}</td>
                                    <td>{comments}</td>
                                    <td>{views}</td>
                                    <td>{added}</td>
                                </tr>
                                '''
                        
                        if not posts_html:
                            posts_html = '''
                            <tr class="paste-row">
                                <td colspan="4" style="text-align: center; color: #666;">No posts yet</td>
                            </tr>
                            '''
                        
                        html_content = html_content.replace('''<tr class="paste-row">
                        <td>Matias Daniel Veron</td>
                        <td>0</td>
                        <td>9</td>
                        <td>Nov 7, 2025</td>
                    </tr>
                    <tr class="paste-row">
                        <td>Scardigli Nelson Daniel</td>
                        <td>0</td>
                        <td>7</td>
                        <td>Nov 7, 2025</td>
                    </tr>
                    <tr class="paste-row">
                        <td>Adios Maria cff</td>
                        <td>0</td>
                        <td>17</td>
                        <td>Nov 7, 2025</td>
                    </tr>
                    <tr class="paste-row">
                        <td>Factura de motor dos</td>
                        <td>0</td>
                        <td>13</td>
                        <td>Nov 7, 2025</td>
                    </tr>
                    <tr class="paste-row">
                        <td>Milagros Nicole</td>
                        <td>0</td>
                        <td>19</td>
                        <td>Nov 7, 2025</td>
                    </tr>''', posts_html)
                        
                        return html_content
                        
            except Exception as e:
                print(f"Error reading user file {filename}: {e}")
                continue
    
    return "User not found", 404

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

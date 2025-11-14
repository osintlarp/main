from flask import Flask, render_template, jsonify, send_file, request, abort
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from PIL import Image, UnidentifiedImageError
from cprint import info, success, error
import os
import uuid
import io
from io import BytesIO
import json
import random
import socket
import string
import secrets
import torch
import timm
import html
import re
import requests
import pyotp
import unicodedata
import qrcode
import ipaddress
import base64
import requests
from pathlib import Path

app = Flask(__name__)
app.debug = True
USER_DIR = "/var/www/users"
MAP_DIR = os.path.join(os.path.expanduser("~"), "map")
MAP_FILE = "root/map/user_map.json"
CONNECT_FILE = os.path.join(USER_DIR, "connect.json")
RUNNER_LIMIT = 1
CF_SECRET_KEY = "0x4AAAAAAB-oyZOuYUUuz-JjT6SN5-XXyeM"
AVATAR_DIR = 'static/avatars'
BANNER_DIR = 'static/banners'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024 
USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{3,30}$')
BANNED_WORDS = [
    "rape", "rapist", "child", "children", "pedo", "pedophile", "molest",
    "sex", "nsfw", "porn", "nude", "incest", "violence", "abuse", "murder",
    "kill", "suicide", "terror", "isis", "hitler", "nazi", "genocide",
    "slave", "kids", "torture", "beastiality", "zoophile", "racist", "racism",
    "blood", "gore", "snuff", "execution", "hang", "dead", "death"
]

if not os.path.exists(USER_DIR):
    os.makedirs(USER_DIR, exist_ok=True)

if not os.path.exists(MAP_DIR):
    os.makedirs(MAP_DIR, exist_ok=True)

if not os.path.exists(MAP_FILE):
    with open(MAP_FILE, 'w') as f:
        json.dump({}, f, indent=4)

def load_json(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)

def load_user_map():
    try:
        with open(MAP_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}

def save_user_map(user_map):
    with open(MAP_FILE, 'w') as f:
        json.dump(user_map, f, indent=4)

def remove_user_from_map(user_id, username):
    user_map = load_user_map()
    if user_id in user_map:
        del user_map[user_id]
    if username in user_map:
        del user_map[username]
    save_user_map(user_map)

def sanitize_username(raw):
    if not raw:
        return None
    s = unicodedata.normalize('NFKC', raw).strip()
    s = s.replace('\x00', '')
    if len(s) < 3 or len(s) > 30:
        return None
    if not USERNAME_RE.match(s):
        return None
    return s

def validate_session(user_data, session_token):
    sessions = user_data.get("session_token", [])
    return any(s.get("session_token") == session_token for s in sessions)

def add_user_to_map(username, user_id, filename, api_key):
    user_map = load_user_map()
    user_entry = {
        "username": username,
        "userID": user_id,
        "filename": filename,
        "api_key": api_key
    }
    user_map[user_id] = user_entry
    user_map[username] = user_entry 
    save_user_map(user_map)

def find_user_by_identifier(identifier):
    user_map = load_user_map()
    
    if identifier in user_map:
        user_info = user_map[identifier]
        user_file = os.path.join(USER_DIR, user_info["filename"])
        if os.path.exists(user_file):
            try:
                with open(user_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, KeyError, Exception):
                return None
    
    try:
        user_files = [f for f in os.listdir(USER_DIR) if f.endswith('.json')]
        for user_file in user_files:
            file_path = os.path.join(USER_DIR, user_file)
            with open(file_path, 'r') as f:
                user_data = json.load(f)
                if (user_data.get('userID') == identifier or 
                    user_data.get('username') == identifier):
                    return user_data
    except Exception:
        pass
    
    return None

def is_proxy_or_hosting(ip):
    try:
        if not ip:
            return False
        if ipaddress.ip_address(ip).is_private:
            return False
        rdns = socket.gethostbyaddr(ip)[0].lower()
        vpn_keywords = [
            "vpn", "cloud", "vps", "host", "aws", "google", "azure",
            "digitalocean", "ovh", "linode", "hetzner", "contabo",
            "m247", "leaseweb", "scaleway", "server", "colo"
        ]
        return any(keyword in rdns for keyword in vpn_keywords)
    except Exception:
        return False
        
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

def generate_unique_fbid(existing_fbids):
    while True:
        length = random.randint(10, 15)
        fbid = str(random.randint(10**(length-1), 10**length - 1))
        if fbid not in existing_fbids:
            return fbid
            
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def resize_image(image_data, max_size=(400, 400)):
    image = Image.open(io.BytesIO(image_data))
    image.thumbnail(max_size, Image.Resampling.LANCZOS)

    if image.mode in ('RGBA', 'P'):
        image = image.convert('RGB')
    
    output = io.BytesIO()
    image.save(output, format='JPEG', quality=85)
    return output.getvalue()

def sanitize_image(image_bytes):
    try:
        image = Image.open(BytesIO(image_bytes))
        image.verify()
    except UnidentifiedImageError:
        raise ValueError("Invalid image format")

    image = Image.open(BytesIO(image_bytes))
    clean = Image.new("RGBA" if image.mode in ("RGBA", "P") else "RGB", image.size)
    clean.paste(image)

    output = BytesIO()
    clean.save(output, format='PNG') 
    return output.getvalue()

def resize_banner(image_bytes, max_width=1920, max_height=600):
    try:
        img = Image.open(BytesIO(image_bytes))
        img.verify()
    except UnidentifiedImageError:
        raise ValueError("Invalid image format")

    img = Image.open(BytesIO(image_bytes))
    img.thumbnail((max_width, max_height))
    clean = Image.new("RGBA" if img.mode in ("RGBA", "P") else "RGB", img.size)
    clean.paste(img)

    output = BytesIO()
    clean.save(output, format='PNG')
    return output.getvalue()

@app.route('/sitemap.xml', methods=['GET'])
def sitemap():
    return send_file('sitemap.xml', mimetype='application/xml')

@app.route("/api/register", methods=["POST"])
def register():
    try:
        data = request.json or {}
        username_raw = data.get("username", "")
        password = data.get("password", "")
        cf_token = data.get("cf_token", "")

        if not username_raw or not password:
            return jsonify({"error": "Username and password required"}), 400
        if not cf_token:
            return jsonify({"error": "CAPTCHA verification required"}), 400

        username = sanitize_username(username_raw)
        if username is None:
            return jsonify({"error": "Invalid username"}), 400

        username_lower = username.lower()
        for word in BANNED_WORDS:
            if word in username_lower:
                return jsonify({"error": "Username contains inappropriate content"}), 400

        verify = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                "secret": CF_SECRET_KEY,
                "response": cf_token,
                "remoteip": request.remote_addr
            },
            timeout=5
        )
        if not verify.ok or not verify.json().get("success"):
            return jsonify({"error": "CAPTCHA verification failed"}), 400

        user_map = load_user_map()
        if user_map is None:
            return jsonify({"error": "User database not available"}), 500

        if username in user_map:
            return jsonify({"error": "Username already exists"}), 400

        existing_fbids = {user_data.get("fbid_v2") for user_data in user_map.values() if user_data.get("fbid_v2")}
        fbid_v2 = generate_unique_fbid(existing_fbids)

        user_id = generate_unique_userid()
        hashed_password = generate_password_hash(password)
        api_key = generate_api_key()
        raw_session_token = secrets.token_hex(32)
        creation_date = datetime.utcnow().isoformat() + "Z"

        user_agent = request.headers.get("User-Agent", "")
        device = "Unknown Device"
        if "Windows" in user_agent:
            device = "Windows PC"
        elif "Macintosh" in user_agent:
            device = "Mac"
        elif "Android" in user_agent:
            device = "Android"
        elif "iPhone" in user_agent or "iPad" in user_agent:
            device = "iOS Device"

        client_ip = request.remote_addr or ""
        hashed_ip = generate_password_hash(client_ip)

        created_using_vpn = is_proxy_or_hosting(client_ip)

        session_entry = {
            "session_token": raw_session_token,
            "user_agent": user_agent,
            "hashed_ip": hashed_ip,
            "created_at": creation_date
        }

        user_data = {
            "userID": user_id,
            "username": username,
            "password": hashed_password,
            "api_key": api_key,
            "session_token": [session_entry],
            "creation_date": creation_date,
            "account_type": "Free",
            "isProfileAvailable": True,
            "isBanned": False,
            "TokenUsage": 0,
            "IsMod": False,
            "fbid_v2": fbid_v2,
            "user_agent": user_agent,
            "device": device,
            "created_using_vpn": created_using_vpn,
            "permissions": {
                "can_change_profilePIC": True,
                "can_change_banner": True,
                "can_change_password": False
            },
            "profile": {
                "profileURL": "/static/avatars/default.jpg",
                "bannerURL": "",
                "has_anonymous_profile_picture": True,
                "Posts": [],
                "Followers": 0,
                "Following": 0,
                "Follower_list": [],
                "Following_list": []
            }
        }

        filename = f"{user_id}.json"
        safe_path = os.path.join(USER_DIR, filename)
        with open(safe_path, "w", encoding="utf-8") as f:
            json.dump(user_data, f, indent=4, ensure_ascii=False)

        add_user_to_map(username, user_id, filename, api_key)

        return jsonify({
            "userID": user_id,
            "sessionToken": raw_session_token,
            "createdUsingVPN": created_using_vpn
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    username_input = data.get("username")
    password_input = data.get("password")

    if not username_input or not password_input:
        return jsonify({"error": "Username/UserID and password required"}), 400

    user_data = find_user_by_identifier(username_input)
    if not user_data:
        return jsonify({"error": "User not found"}), 404

    if user_data.get("isBanned", False):
        return jsonify({"error": "Account is banned"}), 403

    if not check_password_hash(user_data["password"], password_input):
        return jsonify({"error": "Invalid password"}), 401

    raw_session_token = secrets.token_hex(32)
    user_agent = request.headers.get("User-Agent", "")
    client_ip = request.remote_addr or ""
    hashed_ip = generate_password_hash(client_ip)
    creation_date = datetime.utcnow().isoformat() + "Z"

    session_entry = {
        "session_token": raw_session_token,
        "user_agent": user_agent,
        "hashed_ip": hashed_ip,
        "created_at": creation_date
    }

    if "session_token" not in user_data or not isinstance(user_data["session_token"], list):
        user_data["session_token"] = []

    user_data["session_token"].append(session_entry)

    user_file = os.path.join(USER_DIR, f"{user_data['userID']}.json")
    with open(user_file, "w", encoding="utf-8") as fw:
        json.dump(user_data, fw, indent=4, ensure_ascii=False)

    return jsonify({
        "userID": user_data["userID"],
        "sessionToken": raw_session_token,
        "api_key": user_data["api_key"]
    }), 200
    
@app.route("/api/logout", methods=["POST"])
def logout():
    data = request.json or {}
    user_id = data.get("userID")
    session_token = data.get("sessionToken")

    if not user_id or not session_token:
        return jsonify({"error": "userID and sessionToken required"}), 400

    user_data = find_user_by_identifier(user_id)
    if not user_data:
        return jsonify({"error": "User not found"}), 404

    sessions = user_data.get("session_token", [])
    if not any(s.get("session_token") == session_token for s in sessions):
        return jsonify({"error": "Invalid sessionToken"}), 401

    user_data["session_token"] = [s for s in sessions if s.get("session_token") != session_token]

    user_file = os.path.join(USER_DIR, f"{user_id}.json")
    with open(user_file, "w", encoding="utf-8") as f:
        json.dump(user_data, f, indent=4, ensure_ascii=False)

    return jsonify({"message": "Logged out successfully"}), 200

@app.route("/connect/account", methods=["GET"])
def connect_account():
    provider = request.args.get("provider")
    sha = request.args.get("sha")

    if provider != "telegram" or not sha:
        return "Invalid request", 400

    connect_data = load_json(CONNECT_FILE)
    if sha not in connect_data:
        return "Invalid or expired link", 400

    telegram_id = str(connect_data[sha]["telegram_id"])

    session_token = request.cookies.get("sessionToken")
    if not session_token:
        return redirect("/login")

    user_data = None
    user_file_path = None

    for file in os.listdir(USER_DIR):
        if file.endswith(".json"):
            path = os.path.join(USER_DIR, file)
            data = load_json(path)
            for s in data.get("session_token", []):
                if s.get("session_token") == session_token:
                    user_data = data
                    user_file_path = path
                    break
        if user_data:
            break

    if not user_data:
        return redirect("/login")

    user_data["telegram_user_id"] = telegram_id
    save_json(user_file_path, user_data)

    user_map = load_json(MAP_FILE)

    uid = str(user_data["userID"])
    uname = str(user_data["username"])

    if uid in user_map:
        user_map[uid]["telegram_id"] = telegram_id
    if uname in user_map:
        user_map[uname]["telegram_id"] = telegram_id

    save_json(MAP_FILE, user_map)

    del connect_data[sha]
    save_json(CONNECT_FILE, connect_data)

    return {"status": "ok", "telegram_id": telegram_id}
    
@app.route('/api/verify_2fa', methods=['POST'])
def verify_2fa():
    data = request.json or {}
    user_id = data.get('userID')
    session_token = data.get('sessionToken')
    code = data.get('code')

    if not user_id or not session_token or not code:
        return jsonify({'error': 'Missing required parameters'}), 400

    user_data = find_user_by_identifier(user_id)
    if not user_data:
        return jsonify({'error': 'User not found'}), 404

    if not validate_session(user_data, session_token):
        return jsonify({'error': 'Invalid session token'}), 401

    secret = user_data.get('2fa_pending_secret')
    if not secret:
        return jsonify({'error': '2FA setup not initiated'}), 400

    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({'error': 'Invalid verification code'}), 401

    user_data['2fa_enabled'] = True
    user_data['2fa_secret'] = secret
    user_data.pop('2fa_pending_secret', None)

    user_file = os.path.join(USER_DIR, f"{user_id}.json")
    with open(user_file, 'w', encoding="utf-8") as f:
        json.dump(user_data, f, indent=4, ensure_ascii=False)

    return jsonify({'message': '2FA enabled successfully'}), 200

@app.route('/api/disable_2fa', methods=['POST'])
def disable_2fa():
    data = request.json or {}
    user_id = data.get('userID')
    session_token = data.get('sessionToken')

    if not user_id or not session_token:
        return jsonify({'error': 'Missing required parameters'}), 400

    user_data = find_user_by_identifier(user_id)
    if not user_data:
        return jsonify({'error': 'User not found'}), 404

    if not validate_session(user_data, session_token):
        return jsonify({'error': 'Invalid session token'}), 401

    if not user_data.get('2fa_enabled', False):
        return jsonify({'error': '2FA is not enabled'}), 400

    user_data['2fa_enabled'] = False
    user_data.pop('2fa_secret', None)

    user_file = os.path.join(USER_DIR, f"{user_id}.json")
    with open(user_file, 'w', encoding="utf-8") as f:
        json.dump(user_data, f, indent=4, ensure_ascii=False)

    return jsonify({'message': '2FA disabled successfully'}), 200

@app.route('/user/<user_identifier>')
def user_profile(user_identifier):
    if not re.match(r'^[a-zA-Z0-9_-]+$', user_identifier):
        return "Invalid user identifier", 400

    user_data = find_user_by_identifier(user_identifier)
    if not user_data:
        return "User not found", 404

    if user_data.get("isProfileAvailable") is False:
        redacted_username = "[REDACTED]"
        user_id = user_data.get("userID", "Unknown")
        if len(user_id) > 2:
            masked_user_id = ("*" * (len(user_id) - 2)) + user_id[-2:]
        else:
            masked_user_id = "**"
        return render_template(
            'profile_page.html',
            username=html.escape(redacted_username),
            user_id=html.escape(masked_user_id),
            creation_date="Unknown",
            paste_count=0,
            following_count=0,
            followers_count=0,
            posts=[],
            has_posts=False,
            is_logged_in=False,
            is_own_profile=False,
            is_following=False,
            can_interact=False,
            target_user_id=masked_user_id,
            profile_url="/static/avatars/default.jpg",
            banner_url=""
        )

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

    logged_in_user_id = request.cookies.get('userID')
    session_token = request.cookies.get('sessionToken')

    is_own_profile = False
    is_following = False
    can_interact = False

    if logged_in_user_id and session_token:
        current_user_data = find_user_by_identifier(logged_in_user_id)
        if current_user_data and validate_session(current_user_data, session_token):
            is_own_profile = (logged_in_user_id == user_data.get('userID'))
            is_following = user_data.get('userID') in current_user_data.get('Following_list', [])
            can_interact = not is_own_profile

    profile_data = user_data.get('profile', {})
    profile_url = profile_data.get('profileURL', '/static/avatars/default.jpg')
    banner_url = profile_data.get('bannerURL', '/static/banners/default.jpg')

    return render_template(
        'profile_page.html',
        username=html.escape(user_data.get('username', 'Unknown')),
        user_id=html.escape(user_data.get('userID', 'Unknown')),
        creation_date=html.escape(formatted_date),
        paste_count=paste_count,
        following_count=following_count,
        followers_count=followers_count,
        posts=safe_posts,
        has_posts=len(posts) > 0,
        is_logged_in=bool(logged_in_user_id and session_token),
        is_own_profile=is_own_profile,
        is_following=is_following,
        can_interact=can_interact,
        target_user_id=user_data.get('userID'),
        profile_url=html.escape(profile_url),
        banner_url=html.escape(banner_url)
    )

@app.route('/api/check_auth', methods=['POST'])
def check_auth():
    data = request.json or {}
    user_id = data.get('userID')
    session_token = data.get('sessionToken')
    target_user_id = data.get('targetUserID')

    if not user_id or not session_token:
        return jsonify({'is_logged_in': False}), 400

    user_data = find_user_by_identifier(user_id)
    if not user_data:
        return jsonify({'is_logged_in': False}), 404

    if not validate_session(user_data, session_token):
        return jsonify({'is_logged_in': False}), 401

    is_following = False
    if target_user_id and isinstance(user_data.get('Following_list'), list):
        is_following = target_user_id in user_data.get('Following_list', [])

    is_own_profile = (user_id == target_user_id)

    return jsonify({
        'is_logged_in': True,
        'is_following': is_following,
        'is_own_profile': is_own_profile
    })
    
@app.route('/api/follow', methods=['POST'])
def follow_user():
    data = request.json or {}
    current_user_id = data.get('currentUserID')
    session_token = data.get('sessionToken')
    target_user_id = data.get('targetUserID')

    if not current_user_id or not session_token or not target_user_id:
        return jsonify({'error': 'Missing required parameters'}), 400

    current_user_data = find_user_by_identifier(current_user_id)
    if not current_user_data:
        return jsonify({'error': 'Current user not found'}), 404

    if not validate_session(current_user_data, session_token):
        return jsonify({'error': 'Invalid session token'}), 401

    target_user_data = find_user_by_identifier(target_user_id)
    if not target_user_data:
        return jsonify({'error': 'Target user not found'}), 404

    if 'Following_list' not in current_user_data:
        current_user_data['Following_list'] = []
    if 'Follower_list' not in target_user_data:
        target_user_data['Follower_list'] = []

    is_following = target_user_id in current_user_data['Following_list']

    if is_following:
        current_user_data['Following_list'].remove(target_user_id)
        current_user_data['Following'] = max(0, current_user_data.get('Following', 0) - 1)

        if current_user_id in target_user_data['Follower_list']:
            target_user_data['Follower_list'].remove(current_user_id)
            target_user_data['Followers'] = max(0, target_user_data.get('Followers', 0) - 1)

        action = 'unfollowed'
    else:
        current_user_data['Following_list'].append(target_user_id)
        current_user_data['Following'] = current_user_data.get('Following', 0) + 1

        target_user_data['Follower_list'].append(current_user_id)
        target_user_data['Followers'] = target_user_data.get('Followers', 0) + 1

        action = 'followed'

    current_user_file = os.path.join(USER_DIR, f"{current_user_id}.json")
    with open(current_user_file, 'w', encoding='utf-8') as f:
        json.dump(current_user_data, f, indent=4, ensure_ascii=False)

    target_user_file = os.path.join(USER_DIR, f"{target_user_id}.json")
    with open(target_user_file, 'w', encoding='utf-8') as f:
        json.dump(target_user_data, f, indent=4, ensure_ascii=False)

    return jsonify({
        'success': True,
        'action': action,
        'new_followers_count': target_user_data['Followers'],
        'new_following_count': current_user_data['Following']
    })


@app.route('/api/check_follow_status', methods=['POST'])
def check_follow_status():
    data = request.json or {}
    current_user_id = data.get('currentUserID')
    target_user_id = data.get('targetUserID')
    session_token = data.get('sessionToken')

    if not current_user_id or not target_user_id or not session_token:
        return jsonify({'error': 'Missing required parameters'}), 400

    current_user_data = find_user_by_identifier(current_user_id)
    if not current_user_data:
        return jsonify({'error': 'Current user not found'}), 404

    if not validate_session(current_user_data, session_token):
        return jsonify({'error': 'Invalid session token'}), 401

    is_following = target_user_id in current_user_data.get('Following_list', [])

    return jsonify({
        'is_following': is_following,
        'followers_count': current_user_data.get('Followers', 0),
        'following_count': current_user_data.get('Following', 0)
    })
    
@app.route('/api/upload_avatar', methods=['POST'])
def upload_avatar():
    if 'avatar' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['avatar']
    user_id = request.form.get('userID')
    session_token = request.form.get('sessionToken')

    if not user_id or not session_token:
        return jsonify({'error': 'Missing user ID or session token'}), 400

    user_data = find_user_by_identifier(user_id)
    if not user_data:
        return jsonify({'error': 'User not found'}), 404

    if not validate_session(user_data, session_token):
        return jsonify({'error': 'Invalid session token'}), 401

    if not user_data.get('permissions', {}).get('can_change_profilePIC', False):
        return jsonify({'error': 'Permission denied to change profile picture'}), 403

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed. Please use JPG, PNG or GIF.'}), 400

    file_data = file.read()
    if len(file_data) > MAX_FILE_SIZE:
        return jsonify({'error': f'File too large. Max {MAX_FILE_SIZE//(1024*1024)}MB.'}), 400

    file_ext = file.filename.rsplit('.', 1)[1].lower()
    unique_filename = f"{user_id}_{uuid.uuid4().hex[:8]}.{file_ext}"
    filename = secure_filename(unique_filename)
    file_path = os.path.join(AVATAR_DIR, filename)

    try:
        sanitized_image = sanitize_image(file_data)
        with open(file_path, 'wb') as f:
            f.write(sanitized_image)

        if 'profile' not in user_data:
            user_data['profile'] = {}
        old_avatar = user_data['profile'].get('profileURL', '')
        if old_avatar.startswith('/static/avatars/'):
            old_path = os.path.join(AVATAR_DIR, os.path.basename(old_avatar))
            if os.path.exists(old_path):
                try:
                    os.remove(old_path)
                except OSError:
                    pass

        user_data['profile']['profileURL'] = f"/static/avatars/{filename}"
        user_file = os.path.join(USER_DIR, f"{user_id}.json")
        with open(user_file, 'w', encoding='utf-8') as f:
            json.dump(user_data, f, indent=4, ensure_ascii=False)

        return jsonify({
            'message': 'Avatar uploaded successfully',
            'profileURL': f"/static/avatars/{filename}"
        }), 200

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception:
        return jsonify({'error': 'Failed to process image'}), 500
        
@app.route('/user/<identifier>/profile', methods=['GET'])
def get_user_profile(identifier):
    user_data = find_user_by_identifier(identifier)

    if not user_data:
        return jsonify({'error': 'User not found'}), 404

    profile_data = {
        'userID': user_data.get('userID'),
        'username': user_data.get('username'),
        'profileURL': user_data.get('profileURL'),
        'bannerURL': user_data.get('bannerURL'),
        'account_type': user_data.get('account_type')
    }

    return jsonify(profile_data), 200

@app.route('/api/upload_banner', methods=['POST'])
def upload_banner():
    if 'banner' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['banner']
    user_id = request.form.get('userID')
    session_token = request.form.get('sessionToken')

    if not user_id or not session_token:
        return jsonify({'error': 'Missing user ID or session token'}), 400

    user_data = find_user_by_identifier(user_id)
    if not user_data:
        return jsonify({'error': 'User not found'}), 404

    if not validate_session(user_data, session_token):
        return jsonify({'error': 'Invalid session token'}), 401

    if not user_data.get('permissions', {}).get('can_change_banner', False):
        return jsonify({'error': 'Permission denied to change banner'}), 403

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed. Please use JPG, PNG or GIF.'}), 400

    file_data = file.read()
    if len(file_data) > MAX_FILE_SIZE:
        return jsonify({'error': f'File too large. Max {MAX_FILE_SIZE//(1024*1024)}MB.'}), 400

    file_ext = file.filename.rsplit('.', 1)[1].lower()
    unique_filename = f"{user_id}_{uuid.uuid4().hex[:8]}.{file_ext}"
    filename = secure_filename(unique_filename)
    file_path = os.path.join(BANNER_DIR, filename)

    try:
        sanitized_image = resize_banner(file_data)
        with open(file_path, 'wb') as f:
            f.write(sanitized_image)

        if 'profile' not in user_data:
            user_data['profile'] = {}

        old_banner = user_data['profile'].get('bannerURL', '')
        if old_banner.startswith('/static/banners/'):
            old_path = os.path.join(BANNER_DIR, os.path.basename(old_banner))
            if os.path.exists(old_path):
                try:
                    os.remove(old_path)
                except OSError:
                    pass

        user_data['profile']['bannerURL'] = f"/static/banners/{filename}"

        user_file = os.path.join(USER_DIR, f"{user_id}.json")
        with open(user_file, 'w', encoding='utf-8') as f:
            json.dump(user_data, f, indent=4, ensure_ascii=False)

        return jsonify({
            'message': 'Banner uploaded successfully',
            'bannerURL': f"/static/banners/{filename}"
        }), 200

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception:
        return jsonify({'error': 'Failed to process image'}), 500

@app.route('/v1/users', methods=['GET'])
def get_user_data():
    session_token = request.args.get("sessionToken") or request.headers.get("Authorization")
    if not session_token:
        return jsonify({'error': 'Missing sessionToken parameter'}), 400

    try:
        user_files = [f for f in os.listdir(USER_DIR) if f.endswith('.json')]
        user_data = None

        for user_file in user_files:
            file_path = os.path.join(USER_DIR, user_file)
            with open(file_path, 'r', encoding='utf-8') as f:
                current_user_data = json.load(f)
                for s in current_user_data.get('session_token', []):
                    if isinstance(s, dict) and s.get('session_token') == session_token:
                        user_data = current_user_data
                        break
                if user_data:
                    break

        if not user_data:
            return jsonify({'error': 'Invalid session token'}), 401

        username = str(user_data.get('username', '')).replace('<', '').replace('>', '')
        account_type = str(user_data.get('account_type', 'Free')).replace('<', '').replace('>', '')

        profile_data = user_data.get('profile', {})
        profile_url = profile_data.get('profileURL', '/static/avatars/default.jpg')
        banner_url = profile_data.get('bannerURL', '')

        response_data = {
            'userID': user_data.get('userID'),
            'username': username,
            'api_key': user_data.get('api_key'),
            'tokenUsage': user_data.get('TokenUsage', 0),
            'accountType': account_type,
            'profile': {
                'profileURL': profile_url,
                'bannerURL': banner_url
            }
        }

        return jsonify(response_data), 200

    except Exception:
        return jsonify({'error': 'An internal server error occurred'}), 500

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

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/legal")
def legal():
    return render_template("legal.html")

if __name__ == "__main__":
    os.makedirs(AVATAR_DIR, exist_ok=True)
    app.run(host="0.0.0.0", port=5000)

from flask import Flask, render_template, jsonify, send_file, request, abort
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from PIL import Image, UnidentifiedImageError
import os
import uuid
import io
from io import BytesIO
import json
import random
import string
import secrets
import html
import re
import pyotp
import qrcode
import base64
from pathlib import Path

app = Flask(__name__)
app.debug = True
USER_DIR = "/var/www/users"
RUNNER_LIMIT = 1
CF_SECRET_KEY = "0x4AAAAAAB-oyZOuYUUuz-JjT6SN5-XXyeM"
AVATAR_DIR = 'static/avatars'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  

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
        "account_type": "Free",
        "isBanned": False,
        "Posts": [],
        "Followers": 0,
        "Following": 0,
        "Follower_list": [],
        "Following_list": []
    }

    with open(os.path.join(USER_DIR, f"{user_id}.json"), "w") as f:
        json.dump(user_data, f, indent=4)

    return jsonify({"userID": user_id, "sessionToken": session_token}), 201

@app.route('/api/setup_2fa', methods=['POST'])
def setup_2fa():
    data = request.json
    user_id = data.get('userID')
    session_token = data.get('sessionToken')
    
    if not user_id or not session_token:
        return jsonify({'error': 'Missing required parameters'}), 400
    
    user_file = os.path.join(USER_DIR, f"{user_id}.json")
    if not os.path.exists(user_file):
        return jsonify({'error': 'User not found'}), 404
    
    with open(user_file, 'r') as f:
        user_data = json.load(f)
    
    if user_data.get('session_token') != session_token:
        return jsonify({'error': 'Invalid session token'}), 401
        
    secret = pyotp.random_base32()
    
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user_data.get('email', user_data.get('username', 'user')),
        issuer_name='VAUL3T'
    )
    
    qr_code_url = f"https://api.qrserver.com/v1/create-qr-code/?data={provisioning_uri}&size=200x200"

    user_data['2fa_pending_secret'] = secret
    with open(user_file, 'w') as f:
        json.dump(user_data, f, indent=4)
    
    return jsonify({
        'secret': secret,
        'qr_code': qr_code_url
    }), 200

@app.route('/api/verify_2fa', methods=['POST'])
def verify_2fa():
    data = request.json
    user_id = data.get('userID')
    session_token = data.get('sessionToken')
    code = data.get('code')
    
    if not user_id or not session_token or not code:
        return jsonify({'error': 'Missing required parameters'}), 400
    
    user_file = os.path.join(USER_DIR, f"{user_id}.json")
    if not os.path.exists(user_file):
        return jsonify({'error': 'User not found'}), 404
    
    with open(user_file, 'r') as f:
        user_data = json.load(f)
    
    if user_data.get('session_token') != session_token:
        return jsonify({'error': 'Invalid session token'}), 401
    
    secret = user_data.get('2fa_pending_secret')
    if not secret:
        return jsonify({'error': '2FA setup not initiated'}), 400

    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({'error': 'Invalid verification code'}), 401
    
    user_data['2fa_enabled'] = True
    user_data['2fa_secret'] = secret
    if '2fa_pending_secret' in user_data:
        del user_data['2fa_pending_secret']
    
    with open(user_file, 'w') as f:
        json.dump(user_data, f, indent=4)
    
    return jsonify({'message': '2FA enabled successfully'}), 200

@app.route('/api/disable_2fa', methods=['POST'])
def disable_2fa():
    data = request.json
    user_id = data.get('userID')
    session_token = data.get('sessionToken')
    
    if not user_id or not session_token:
        return jsonify({'error': 'Missing required parameters'}), 400
    
    user_file = os.path.join(USER_DIR, f"{user_id}.json")
    if not os.path.exists(user_file):
        return jsonify({'error': 'User not found'}), 404
    
    with open(user_file, 'r') as f:
        user_data = json.load(f)
    
    if user_data.get('session_token') != session_token:
        return jsonify({'error': 'Invalid session token'}), 401
    
    if not user_data.get('2fa_enabled'):
        return jsonify({'error': '2FA is not enabled'}), 400

    user_data['2fa_enabled'] = False
    if '2fa_secret' in user_data:
        del user_data['2fa_secret']
    
    with open(user_file, 'w') as f:
        json.dump(user_data, f, indent=4)
    
    return jsonify({'message': '2FA disabled successfully'}), 200

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
    
    logged_in_user_id = request.cookies.get('userID')
    session_token = request.cookies.get('sessionToken')
    
    is_own_profile = False
    is_following = False
    
    if logged_in_user_id and session_token:
        current_user_file = os.path.join(USER_DIR, f"{logged_in_user_id}.json")
        if os.path.exists(current_user_file):
            with open(current_user_file, 'r') as f:
                current_user_data = json.load(f)
                if current_user_data.get('session_token') == session_token:
                    is_own_profile = (logged_in_user_id == user_data.get('userID'))
                    is_following = user_data.get('userID') in current_user_data.get('Following_list', [])
    
    return render_template('profile_page.html',
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
                         target_user_id=user_data.get('userID'))

@app.route('/api/check_auth', methods=['POST'])
def check_auth():
    data = request.json
    user_id = data.get('userID')
    session_token = data.get('sessionToken')
    target_user_id = data.get('targetUserID')
    
    if not user_id or not session_token:
        return jsonify({'is_logged_in': False}), 400
    
    user_file = os.path.join(USER_DIR, f"{user_id}.json")
    if not os.path.exists(user_file):
        return jsonify({'is_logged_in': False}), 404
    
    with open(user_file, 'r') as f:
        user_data = json.load(f)
    
    if user_data.get('session_token') != session_token:
        return jsonify({'is_logged_in': False}), 401

    is_following = target_user_id in user_data.get('Following_list', [])
    is_own_profile = (user_id == target_user_id)
    
    return jsonify({
        'is_logged_in': True,
        'is_following': is_following,
        'is_own_profile': is_own_profile
    })

@app.route('/api/follow', methods=['POST'])
def follow_user():
    data = request.json
    current_user_id = data.get('currentUserID')
    session_token = data.get('sessionToken')
    target_user_id = data.get('targetUserID')
    
    if not current_user_id or not session_token or not target_user_id:
        return jsonify({'error': 'Missing required parameters'}), 400
    
    current_user_file = os.path.join(USER_DIR, f"{current_user_id}.json")
    if not os.path.exists(current_user_file):
        return jsonify({'error': 'Current user not found'}), 404
    
    with open(current_user_file, 'r') as f:
        current_user_data = json.load(f)
    
    if current_user_data.get('session_token') != session_token:
        return jsonify({'error': 'Invalid session token'}), 401

    target_user_file = os.path.join(USER_DIR, f"{target_user_id}.json")
    if not os.path.exists(target_user_file):
        return jsonify({'error': 'Target user not found'}), 404
    
    with open(target_user_file, 'r') as f:
        target_user_data = json.load(f)
    
    is_following = target_user_id in current_user_data.get('Following_list', [])
    
    if is_following:
        if target_user_id in current_user_data['Following_list']:
            current_user_data['Following_list'].remove(target_user_id)
            current_user_data['Following'] = max(0, current_user_data.get('Following', 0) - 1)
        
        if current_user_id in target_user_data['Follower_list']:
            target_user_data['Follower_list'].remove(current_user_id)
            target_user_data['Followers'] = max(0, target_user_data.get('Followers', 0) - 1)
        
        action = 'unfollowed'
    else:
        if 'Following_list' not in current_user_data:
            current_user_data['Following_list'] = []
        if target_user_id not in current_user_data['Following_list']:
            current_user_data['Following_list'].append(target_user_id)
            current_user_data['Following'] = current_user_data.get('Following', 0) + 1
        
        if 'Follower_list' not in target_user_data:
            target_user_data['Follower_list'] = []
        if current_user_id not in target_user_data['Follower_list']:
            target_user_data['Follower_list'].append(current_user_id)
            target_user_data['Followers'] = target_user_data.get('Followers', 0) + 1
        
        action = 'followed'
    
    with open(current_user_file, 'w') as f:
        json.dump(current_user_data, f, indent=4)
    
    with open(target_user_file, 'w') as f:
        json.dump(target_user_data, f, indent=4)
    
    return jsonify({
        'success': True,
        'action': action,
        'new_followers_count': target_user_data['Followers'],
        'new_following_count': current_user_data['Following']
    })

@app.route('/api/check_follow_status', methods=['POST'])
def check_follow_status():
    data = request.json
    current_user_id = data.get('currentUserID')
    target_user_id = data.get('targetUserID')
    
    if not current_user_id or not target_user_id:
        return jsonify({'error': 'Missing required parameters'}), 400
    
    current_user_file = os.path.join(USER_DIR, f"{current_user_id}.json")
    if not os.path.exists(current_user_file):
        return jsonify({'error': 'Current user not found'}), 404
    
    with open(current_user_file, 'r') as f:
        current_user_data = json.load(f)
    
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

    user_file = os.path.join(USER_DIR, f"{user_id}.json")
    if not os.path.exists(user_file):
        return jsonify({'error': 'User not found'}), 404

    with open(user_file, 'r', encoding='utf-8') as f:
        user_data = json.load(f)

    if user_data.get('session_token') != session_token:
        return jsonify({'error': 'Invalid session token'}), 401

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed. Please use JPG, PNG or GIF.'}), 400

    file_data = file.read()
    if len(file_data) > MAX_FILE_SIZE:
        return jsonify({'error': 'File too large. Max 5MB.'}), 400

    file_ext = file.filename.rsplit('.', 1)[1].lower()
    unique_filename = f"{user_id}_{uuid.uuid4().hex[:8]}.{file_ext}"
    filename = secure_filename(unique_filename)
    file_path = os.path.join(AVATAR_DIR, filename)

    try:
        sanitized_image = sanitize_image(file_data)

        with open(file_path, 'wb') as f:
            f.write(sanitized_image)

        old_avatar = user_data.get('profileURL', '')
        if old_avatar.startswith('/static/avatars/'):
            old_path = os.path.join(AVATAR_DIR, os.path.basename(old_avatar))
            if os.path.exists(old_path):
                try:
                    os.remove(old_path)
                except OSError:
                    pass

        user_data['profileURL'] = f"/static/avatars/{filename}"
        with open(user_file, 'w', encoding='utf-8') as f:
            json.dump(user_data, f, indent=4, ensure_ascii=False)

        return jsonify({
            'message': 'Avatar uploaded successfully',
            'profileURL': f"/static/avatars/{filename}"
        }), 200

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        print(f"[ERROR] Avatar upload failed: {e}")
        return jsonify({'error': 'Failed to process image'}), 500

@app.route('/user/<identifier>/profile', methods=['GET'])
def get_user_profile(identifier):
    try:
        user_id = int(identifier)
        user_file = os.path.join(USER_DIR, f"{user_id}.json")
        if os.path.isfile(user_file):
            with open(user_file, 'r', encoding='utf-8') as f:
                user_data = json.load(f)
        else:
            user_data = None
    except ValueError:
        if not re.match(r'^[A-Za-z0-9_-]{1,32}$', identifier):
            return jsonify({'error': 'Invalid username format'}), 400
        user_data = None
        for filename in os.listdir(USER_DIR):
            if filename.endswith('.json'):
                file_path = os.path.join(USER_DIR, filename)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if data.get('username') == identifier:
                            user_data = data
                            break
                except json.JSONDecodeError:
                    continue
    except Exception:
        return jsonify({'error': 'Internal server error'}), 500

    if not user_data:
        return jsonify({'error': 'User not found'}), 404

    profile_url = user_data.get('profileURL')
    return jsonify({'profileURL': profile_url if profile_url else None}), 200
        
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

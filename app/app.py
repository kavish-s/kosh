from flask import Flask, request, send_file, render_template, redirect, url_for, session, jsonify, flash
import socket
from flask_cors import CORS
from .crypto import aes, abe_simulator as abe
import os, json
from io import BytesIO

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
DATA_DIR = os.path.join(BASE_DIR, 'data')
USER_KEYS_DIR = os.path.join(BASE_DIR, 'user_keys')

app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
app.secret_key = 'kosh-secret-key'
CORS(app)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(USER_KEYS_DIR, exist_ok=True)

USERS_FILE = os.path.join(DATA_DIR, 'users.json')
POLICIES_FILE = os.path.join(DATA_DIR, 'policies.json')

# Initial dummy data if not exists
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'w') as f:
        json.dump({"user1": ["student", "year3"], "user2": ["faculty"]}, f)

if not os.path.exists(POLICIES_FILE):
    with open(POLICIES_FILE, 'w') as f:
        json.dump({}, f)

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


# Only allow non-admin users to login via /login
@app.route('/login', methods=['POST'])
def login():
    user_id = request.form.get('user_id')
    if user_id == 'admin':
        # Redirect to /admin for password prompt
        return redirect(url_for('admin_dashboard'))
    with open(USERS_FILE) as f:
        users = json.load(f)
    if user_id in users:
        session['user_id'] = user_id
        return redirect(url_for('dashboard'))
    return "Invalid user", 401

@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('home'))

    with open(POLICIES_FILE) as f:
        policies = json.load(f)

    # Support both old and new policy formats
    user_files = []
    for fname, policy in policies.items():
        # If policy is dict, new format; else, old format
        if isinstance(policy, dict):
            access_policy = policy.get('policy')
            sender = policy.get('sender')
        else:
            access_policy = policy
            sender = None
        # Always convert access_policy to a list of attributes
        if isinstance(access_policy, str):
            required_attrs = [a.strip() for a in access_policy.split(',') if a.strip()]
        elif isinstance(access_policy, list):
            required_attrs = access_policy
        else:
            required_attrs = []
        if abe.check_access(session['user_id'], required_attrs):
            user_files.append({'filename': fname, 'sender': sender})

    # Get local IP address
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        server_ip = s.getsockname()[0]
        s.close()
    except Exception:
        server_ip = "localhost"

    return render_template('dashboard.html', user_id=user_id, files=user_files, server_ip=server_ip)

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('home'))
    files = request.files.getlist('file')
    policy = request.form.get('policy')

    # Defensive conversion
    if isinstance(policy, dict):
        policy = ' AND '.join([f"{k}={v}" for k, v in policy.items()])
    elif isinstance(policy, list):
        policy = ' AND '.join(policy)

    uploaded_files = []
    with open(POLICIES_FILE) as f:
        policies = json.load(f)

    for file in files:
        filename = file.filename + '.enc'
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        with open(filepath, 'wb') as f_out:
            aes.encrypt(file.stream, f_out)
        policies[filename] = {'policy': policy, 'sender': session['user_id']}
        uploaded_files.append(filename)

    with open(POLICIES_FILE, 'w') as f:
        json.dump(policies, f)

    return jsonify(success=True, filenames=uploaded_files)

@app.route('/download/<filename>')
def download(filename):
    if 'user_id' not in session:
        return redirect(url_for('home'))
    with open(POLICIES_FILE) as f:
        policies = json.load(f)
    policy_obj = policies.get(filename)
    if not policy_obj:
        return "Access Denied", 403
    access_policy = policy_obj.get('policy') if isinstance(policy_obj, dict) else policy_obj
    if isinstance(access_policy, str):
        required_attrs = [a.strip() for a in access_policy.split(',') if a.strip()]
    elif isinstance(access_policy, list):
        required_attrs = access_policy
    else:
        required_attrs = []
    if not abe.check_access(session['user_id'], required_attrs):
        return "Access Denied", 403

    encrypted_path = os.path.join(UPLOAD_FOLDER, filename)
    decrypted_stream = BytesIO()
    
    try:
        with open(encrypted_path, 'rb') as f_in:
            aes.decrypt(f_in, decrypted_stream)
    except FileNotFoundError:
        return "File not found", 404
    except ValueError as e:
        # This will catch HMAC verification errors
        print(f"Decryption or verification failed for {filename}: {e}")
        return "Access Denied: File is corrupt or has been tampered with.", 403

    decrypted_stream.seek(0)
    return send_file(decrypted_stream, download_name=filename.replace(".enc", ""), as_attachment=True)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


# Admin password (in production, use env var or hashed password)
ADMIN_PASSWORD = 'Admin@2025'  # Change this to a strong password

@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    # If not logged in as admin, show password prompt
    if session.get('user_id') != 'admin':
        if request.method == 'POST':
            password = request.form.get('password')
            if password == ADMIN_PASSWORD:
                session['user_id'] = 'admin'
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Incorrect admin password.', 'danger')
        return render_template('admin_login.html')
    with open(USERS_FILE) as f:
        users = json.load(f)
    with open(POLICIES_FILE) as f:
        policies = json.load(f)
    return render_template('admin.html', users=users, policies=policies)

# --- Admin User Management Routes ---
@app.route('/admin/add_user', methods=['GET', 'POST'])
def admin_add_user():
    if session.get('user_id') != 'admin':
        return redirect(url_for('home'))
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        attributes = request.form.get('attributes', '').split(',')
        attributes = [a.strip() for a in attributes if a.strip()]
        with open(USERS_FILE) as f:
            users = json.load(f)
        users[user_id] = attributes
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_add_user.html')

@app.route('/admin/edit_user/<user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    if session.get('user_id') != 'admin':
        return redirect(url_for('home'))
    with open(USERS_FILE) as f:
        users = json.load(f)
    if request.method == 'POST':
        attributes = request.form.get('attributes', '').split(',')
        attributes = [a.strip() for a in attributes if a.strip()]
        users[user_id] = attributes
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
        return redirect(url_for('admin_dashboard'))
    attrs = ','.join(users.get(user_id, []))
    return render_template('admin_edit_user.html', user_id=user_id, attributes=attrs)

@app.route('/admin/delete_user/<user_id>')
def admin_delete_user(user_id):
    if session.get('user_id') != 'admin':
        return redirect(url_for('home'))
    with open(USERS_FILE) as f:
        users = json.load(f)
    users.pop(user_id, None)
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)
    return redirect(url_for('admin_dashboard'))

# --- Admin Policy Management Routes ---
@app.route('/admin/add_policy', methods=['GET', 'POST'])
def admin_add_policy():
    if session.get('user_id') != 'admin':
        return redirect(url_for('home'))
    if request.method == 'POST':
        file = request.form.get('file')
        policy = request.form.get('policy')
        key = request.form.get('key', '')
        with open(POLICIES_FILE) as f:
            policies = json.load(f)
        policies[file] = {"policy": policy}
        if key:
            policies[file]["key"] = key
        with open(POLICIES_FILE, 'w') as f:
            json.dump(policies, f, indent=2)
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_add_policy.html')

@app.route('/admin/edit_policy/<file>', methods=['GET', 'POST'])
def admin_edit_policy(file):
    if session.get('user_id') != 'admin':
        return redirect(url_for('home'))
    with open(POLICIES_FILE) as f:
        policies = json.load(f)
    if request.method == 'POST':
        policy = request.form.get('policy')
        key = request.form.get('key', '')
        policies[file] = {"policy": policy}
        if key:
            policies[file]["key"] = key
        with open(POLICIES_FILE, 'w') as f:
            json.dump(policies, f, indent=2)
        return redirect(url_for('admin_dashboard'))
    policy_val = policies.get(file, {}).get('policy', '')
    key_val = policies.get(file, {}).get('key', '')
    return render_template('admin_edit_policy.html', file=file, policy=policy_val, key=key_val)

@app.route('/admin/delete_policy/<file>')
def admin_delete_policy(file):
    if session.get('user_id') != 'admin':
        return redirect(url_for('home'))
    with open(POLICIES_FILE) as f:
        policies = json.load(f)
    policies.pop(file, None)
    with open(POLICIES_FILE, 'w') as f:
        json.dump(policies, f, indent=2)
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True, port=7130, host="0.0.0.0")

from flask import (
    Flask,
    request,
    send_file,
    render_template,
    redirect,
    url_for,
    session,
    jsonify,
    flash,
)
from .attribute_management import attribute_bp
import socket
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from .crypto import aes, abe_simulator as abe
import os, json
from datetime import datetime
from io import BytesIO

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
DATA_DIR = os.path.join(
    os.path.dirname(BASE_DIR), "data"
)  # Go up one level to project root
USER_KEYS_DIR = os.path.join(BASE_DIR, "user_keys")


app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
app.secret_key = "kosh-secret-key"
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(USER_KEYS_DIR, exist_ok=True)
app.register_blueprint(attribute_bp)

USERS_FILE = os.path.join(DATA_DIR, "users.json")

POLICIES_FILE = os.path.join(DATA_DIR, "policies.json")
AUDIT_LOG_FILE = os.path.join(DATA_DIR, "audit_logs.jsonl")


def safe_load_json(file_path, default_value=None):
    """Safely load JSON from a file, handling empty files and JSON decode errors."""
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        # Initialize with default value if file is corrupted or missing
        if default_value is None:
            default_value = {}
        with open(file_path, "w") as f:
            json.dump(default_value, f)
        return default_value


def log_audit(user, action, details=None, ip=None):
    """Log audit events with proper error handling"""
    try:
        entry = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "user": str(user) if user else "unknown",
            "action": str(action) if action else "unknown",
            "details": str(details) if details else "",
            "ip": str(ip) if ip else "",
        }

        with open(AUDIT_LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

        # Emit real-time audit log update to admin dashboard
        socketio.emit("audit_log_added", entry, room="admin_updates")

    except Exception as e:
        # Log to console if audit logging fails
        print(f"Audit logging failed: {e}")


def get_user_files(user_id):
    """Get list of files accessible to a user"""
    policies = safe_load_json(POLICIES_FILE, {})
    user_files = []
    is_admin = user_id == "admin"

    if is_admin:
        # Admin sees all files
        for fname, policy in policies.items():
            if isinstance(policy, dict):
                sender = policy.get("sender")
            else:
                sender = None
            user_files.append(
                {
                    "filename": fname,
                    "sender": sender,
                    "is_owner": True,  # Admin can delete any file
                }
            )
    else:
        for fname, policy in policies.items():
            if isinstance(policy, dict):
                access_policy = policy.get("policy")
                sender = policy.get("sender")
            else:
                access_policy = policy
                sender = None

            # Check if user is the owner
            is_owner = sender == user_id

            # If user is owner, they can always access their file
            has_access = is_owner

            # If not owner, check access policy
            if not has_access:
                # Normalize access_policy into a list of attributes
                if isinstance(access_policy, str):
                    required_attrs = [
                        a.strip() for a in access_policy.split(",") if a.strip()
                    ]
                elif isinstance(access_policy, list):
                    required_attrs = access_policy
                else:
                    required_attrs = []

                try:
                    has_access = abe.check_access(user_id, required_attrs)
                except Exception:
                    has_access = False

            if has_access:
                user_files.append(
                    {"filename": fname, "sender": sender, "is_owner": is_owner}
                )

    return user_files


def parse_and_validate_attrs(raw):
    """Normalize raw attributes input into a deduplicated list and validate format.

    Accepts a list or comma-separated string. Returns (attrs_list, error_message).
    Valid attribute tokens match /^[A-Za-z0-9_-]+$/.
    """
    if raw is None:
        return [], None
    if isinstance(raw, list):
        tokens = [str(x).strip() for x in raw if str(x).strip()]
    elif isinstance(raw, str):
        tokens = [t.strip() for t in raw.split(",") if t.strip()]
    else:
        # unsupported type
        return None, "Invalid attributes format"

    # validate tokens
    import re

    pat = re.compile(r"^[A-Za-z0-9_-]+$")
    cleaned = []
    seen = set()
    for t in tokens:
        if not pat.match(t):
            return None, f'Invalid attribute: "{t}"'
        if t in seen:
            continue
        seen.add(t)
        cleaned.append(t)
    return cleaned, None


# Initial dummy data if not exists
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w") as f:
        json.dump(
            {
                "user1": {"attributes": ["student", "year3"], "password": "pass"},
                "user2": {"attributes": ["faculty"], "password": "pass"},
            },
            f,
        )

if not os.path.exists(POLICIES_FILE):
    with open(POLICIES_FILE, "w") as f:
        json.dump({}, f)


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    user_id = request.form.get("user_id")
    password = request.form.get("password")

    # Input validation
    if not user_id or not password:
        return "Username and password are required", 400

    # Sanitize inputs
    user_id = user_id.strip()
    if not user_id:
        return "Username cannot be empty", 400

    try:
        with open(USERS_FILE) as f:
            users = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return "System error: Unable to load user data", 500

    # Verify user exists
    if user_id in users:
        expected = (
            users[user_id].get("password") if isinstance(users[user_id], dict) else None
        )
        if expected == password:
            # Set session for admin or regular users
            session["user_id"] = user_id
            # Log login event
            log_audit(
                user_id, "login", details="Login successful", ip=request.remote_addr
            )
            if user_id == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))
        else:
            log_audit(
                user_id,
                "login_failed",
                details="Invalid password",
                ip=request.remote_addr,
            )
            return "Invalid password", 401
    log_audit(user_id, "login_failed", details="Invalid user", ip=request.remote_addr)
    return "Invalid user", 401


@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("home"))

    # Get user files using the helper function
    user_files = get_user_files(user_id)

    # Get local IP address for share info
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        server_ip = s.getsockname()[0]
        s.close()
    except Exception:
        server_ip = "localhost"

    # Load all attributes for attribute selection UI
    ATTRIBUTES_FILE = os.path.join(DATA_DIR, "attributes.json")
    user_attrs = set()
    # Load user attributes from USERS_FILE
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE) as f:
            users = json.load(f)
        for u, v in (users or {}).items():
            if isinstance(v, dict):
                attrs = v.get("attributes") or []
            elif isinstance(v, list):
                attrs = v
            else:
                attrs = []
            for a in attrs:
                if isinstance(a, str) and "," in a:
                    for part in a.split(","):
                        user_attrs.add(part.strip())
                else:
                    user_attrs.add(a)
    # Load attributes.json
    if os.path.exists(ATTRIBUTES_FILE):
        with open(ATTRIBUTES_FILE) as f:
            all_attributes = set(json.load(f))
    else:
        all_attributes = set()
    # Merge user attributes into global list
    for a in user_attrs:
        if a and a not in all_attributes:
            all_attributes.add(a)
    all_attributes = sorted(list(all_attributes))
    return render_template(
        "dashboard.html",
        user_id=user_id,
        files=user_files,
        server_ip=server_ip,
        all_attributes=all_attributes,
    )


# API endpoint to get updated file list
@app.route("/api/files")
def api_files():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    user_files = get_user_files(user_id)
    return jsonify({"files": user_files})


# Route for changing password
@app.route("/change_password", methods=["POST"])
def change_password():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("home"))

    new_password = request.form.get("new_password")

    # Input validation
    if not new_password:
        flash("Password cannot be empty")
        return redirect(url_for("dashboard"))

    # Sanitize and validate password
    new_password = new_password.strip()
    if len(new_password) < 6:
        flash("Password must be at least 6 characters long")
        return redirect(url_for("dashboard"))

    try:
        with open(USERS_FILE) as f:
            users = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        flash("System error: Unable to load user data")
        return redirect(url_for("dashboard"))

    if user_id in users:
        users[user_id]["password"] = new_password
        try:
            with open(USERS_FILE, "w") as f:
                json.dump(users, f, indent=2)
            log_audit(
                user_id,
                "change_password",
                details="Password changed",
                ip=request.remote_addr,
            )
            flash("Password changed successfully!")
            return redirect(url_for("dashboard"))
        except IOError:
            flash("System error: Unable to save password change")
            return redirect(url_for("dashboard"))

    flash("User not found")
    return redirect(url_for("dashboard"))


@app.route("/upload", methods=["POST"])
def upload():
    if "user_id" not in session:
        return jsonify(success=False, error="Not authenticated"), 401

    files = request.files.getlist("file")
    policy = request.form.get("policy", "")

    # Input validation
    if not files or all(not file.filename for file in files):
        return jsonify(success=False, error="No files selected"), 400

    # Validate file types and sizes
    # Allow more secure file types: documents, images, archives, code, spreadsheets, presentations
    allowed_extensions = {
        # Documents, spreadsheets, presentations
        "txt",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "csv",
        "rtf",
        "odt",
        "ods",
        "odp",
        # Images
        "jpg",
        "jpeg",
        "png",
        "gif",
        "bmp",
        "tiff",
        "webp",
        # Archives
        "zip",
        "rar",
        "7z",
        "tar",
        "gz",
        "bz2",
        # Code and config
        "py",
        "js",
        "json",
        "xml",
        "html",
        "css",
        "md",
        "yml",
        "yaml",
        "c",
        "cpp",
        "h",
        "hpp",
        "java",
        "go",
        "rb",
        "php",
        "sh",
        "swift",
        "ts",
        "rs",
        "pl",
        "sql",
        # Executables and installers
        "apk",
        "exe",
        "dll",
        "so",
        "bin",
        "iso",
        "dmg",
        "app",
        "deb",
        "rpm",
        "msi",
        "bat",
        "ps1",
        # Video files
        "mp4",
        "mov",
        "avi",
        "wmv",
        "flv",
        "mkv",
        "webm",
        "mpeg",
        "mpg",
        "m4v",
        "3gp",
        "ts",
        "vob",
        "ogv",
        "mxf",
        "rm",
        "swf",
    }
    max_file_size = 5 * 1024 * 1024 * 1024  # 5GB

    for file in files:
        if not file.filename:
            continue

        # Check file extension
        if "." in file.filename:
            ext = file.filename.rsplit(".", 1)[1].lower()
            # Accept both lower and upper case extensions
            if ext not in allowed_extensions and ext.upper() not in allowed_extensions:
                return (
                    jsonify(success=False, error=f"File type .{ext} not allowed"),
                    400,
                )

        # Check file size
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > max_file_size:
            return (
                jsonify(
                    success=False, error=f"File {file.filename} is too large (max 10MB)"
                ),
                400,
            )

    # Sanitize policy input
    policy = policy.strip()

    try:
        policies = safe_load_json(POLICIES_FILE, {})
    except Exception:
        return (
            jsonify(success=False, error="System error: Unable to load policies"),
            500,
        )

    uploaded_files = []

    for file in files:
        if not file.filename:
            continue

        try:
            # Generate secure filename
            original_filename = file.filename
            filename = original_filename + ".enc"

            # Ensure filename is safe
            filename = os.path.basename(filename)

            filepath = os.path.join(UPLOAD_FOLDER, filename)

            # Encrypt and save file
            with open(filepath, "wb") as f_out:
                aes.encrypt(file.stream, f_out)

            policies[filename] = {"policy": policy, "sender": session["user_id"]}
            uploaded_files.append(filename)

            # Log upload event for each file
            log_audit(
                session["user_id"],
                "upload",
                details=f"Uploaded {original_filename}",
                ip=request.remote_addr,
            )

        except Exception as e:
            # Clean up any partially uploaded files
            for uploaded_file in uploaded_files:
                try:
                    os.remove(os.path.join(UPLOAD_FOLDER, uploaded_file))
                except:
                    pass
            return jsonify(success=False, error=f"Upload failed: {str(e)}"), 500

    try:
        with open(POLICIES_FILE, "w") as f:
            json.dump(policies, f, indent=2)
    except IOError:
        return (
            jsonify(success=False, error="System error: Unable to save policies"),
            500,
        )

    # Broadcast file update to all connected dashboard users
    socketio.emit(
        "file_uploaded",
        {"uploader": session["user_id"], "files": uploaded_files},
        room="dashboard_updates",
    )

    return jsonify(success=True, filenames=uploaded_files)


@app.route("/download/<filename>")
def download(filename):
    if "user_id" not in session:
        return redirect(url_for("home"))

    user_id = session["user_id"]

    # Input validation and sanitization
    if not filename:
        return "Invalid filename", 400

    # Prevent directory traversal attacks
    filename = os.path.basename(filename)
    if not filename or filename in [".", ".."] or "/" in filename or "\\" in filename:
        return "Invalid filename", 400

    # Ensure filename has .enc extension for security
    if not filename.endswith(".enc"):
        return "Access Denied", 403

    try:
        if user_id == "admin":
            pass  # admin can download any file
        else:
            policies = safe_load_json(POLICIES_FILE, {})
            policy_obj = policies.get(filename)
            if not policy_obj:
                return "Access Denied", 403
            access_policy = (
                policy_obj.get("policy") if isinstance(policy_obj, dict) else policy_obj
            )
            sender = policy_obj.get("sender") if isinstance(policy_obj, dict) else None
            # Owners can always download their own files
            if sender == user_id:
                pass
            else:
                if isinstance(access_policy, str):
                    required_attrs = [
                        a.strip() for a in access_policy.split(",") if a.strip()
                    ]
                elif isinstance(access_policy, list):
                    required_attrs = access_policy
                else:
                    required_attrs = []
                if not abe.check_access(user_id, required_attrs):
                    return "Access Denied", 403
    except Exception as e:
        print(f"Error checking access for {filename}: {e}")
        return "Access Denied", 403

    encrypted_path = os.path.join(UPLOAD_FOLDER, filename)
    decrypted_stream = BytesIO()

    try:
        with open(encrypted_path, "rb") as f_in:
            aes.decrypt(f_in, decrypted_stream)
    except FileNotFoundError:
        return "File not found", 404
    except ValueError as e:
        # This will catch HMAC verification errors
        print(f"Decryption or verification failed for {filename}: {e}")
        return "Access Denied: File is corrupt or has been tampered with.", 403
    except Exception as e:
        print(f"Unexpected error during decryption for {filename}: {e}")
        return "System error: Unable to process file", 500

    # Log download event
    log_audit(
        session["user_id"],
        "download",
        details=f"Downloaded {filename}",
        ip=request.remote_addr,
    )

    decrypted_stream.seek(0)
    original_name = filename.replace(".enc", "")
    return send_file(decrypted_stream, download_name=original_name, as_attachment=True)


@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    if user_id:
        log_audit(user_id, "logout", details="User logged out", ip=request.remote_addr)
    session.clear()
    return redirect(url_for("home"))


@app.route("/admin")
def admin_dashboard():
    """Admin dashboard — only accessible to admin user"""
    if session.get("user_id") != "admin":
        return redirect(url_for("home"))

    # Load users and policies with error handling
    try:
        with open(USERS_FILE) as f:
            users = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        users = {}

    try:
        with open(POLICIES_FILE) as f:
            policies = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        policies = {}

    # Admin sees all files, regardless of policy
    all_files = []
    try:
        for fname in os.listdir(UPLOAD_FOLDER):
            fpath = os.path.join(UPLOAD_FOLDER, fname)
            if not os.path.isfile(fpath):
                continue
            size = os.path.getsize(fpath)
            mtime = os.path.getmtime(fpath)
            upload_date = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
            owner = None
            # Try to get owner from policies if available
            p = policies.get(fname) if isinstance(policies, dict) else None
            if isinstance(p, dict):
                owner = p.get("sender")
            all_files.append(
                {
                    "name": fname,
                    "size": size,
                    "owner": owner,
                    "upload_date": upload_date,
                }
            )
    except (OSError, IOError):
        all_files = []

    # Load audit logs from file
    audit_logs = []
    try:
        with open(AUDIT_LOG_FILE) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    audit_logs.append(entry)
                except json.JSONDecodeError:
                    continue
    except (IOError, OSError):
        audit_logs = []
    audit_logs = list(reversed(audit_logs))  # latest first

    # Load global attribute list from attributes.json
    ATTRIBUTES_FILE = os.path.join(DATA_DIR, "attributes.json")
    user_attrs = set()
    for u, v in (users or {}).items():
        if isinstance(v, dict):
            attrs = v.get("attributes") or []
        elif isinstance(v, list):
            attrs = v
        else:
            attrs = []
        for a in attrs:
            # Split comma-separated attributes if present
            if isinstance(a, str) and "," in a:
                for part in a.split(","):
                    user_attrs.add(part.strip())
            else:
                user_attrs.add(a)
    # Load attributes.json
    if os.path.exists(ATTRIBUTES_FILE):
        with open(ATTRIBUTES_FILE) as f:
            all_attributes = set(json.load(f))
    else:
        all_attributes = set()
    # Merge user attributes into global list
    updated = False
    for a in user_attrs:
        if a and a not in all_attributes:
            all_attributes.add(a)
            updated = True
    all_attributes = sorted(list(all_attributes))
    # Save if updated
    if updated:
        with open(ATTRIBUTES_FILE, "w") as f:
            json.dump(all_attributes, f, indent=2)

    return render_template(
        "admin.html",
        users=users,
        policies=policies,
        all_files=all_files,
        audit_logs=audit_logs,
        all_attributes=all_attributes,
    )


# --- Admin User Management Routes ---
@app.route("/admin/add_user", methods=["GET", "POST"])
def admin_add_user():
    if session.get("user_id") != "admin":
        return redirect(url_for("home"))
    if request.method == "POST":
        # Support both form-encoded and JSON (AJAX) submissions
        is_ajax = (
            request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or request.is_json
            or "application/json" in request.headers.get("Accept", "")
        )
        if request.is_json:
            data = request.get_json() or {}
            user_id = data.get("user") or data.get("user_id")
            raw = data.get("attrs") or data.get("attributes") or ""
        else:
            user_id = request.form.get("user_id") or request.form.get("user")
            raw = request.form.get("attributes", "")

        # Input validation and sanitization
        if not user_id:
            if is_ajax:
                return jsonify(success=False, error="user required"), 400
            return "User required", 400

        user_id = user_id.strip()
        if not user_id:
            if is_ajax:
                return jsonify(success=False, error="user cannot be empty"), 400
            return "User cannot be empty", 400

        # Validate user_id format (alphanumeric, underscore, dash only)
        import re

        if not re.match(r"^[A-Za-z0-9_-]+$", user_id):
            if is_ajax:
                return jsonify(success=False, error="Invalid user ID format"), 400
            return "Invalid user ID format", 400

        attributes, err = parse_and_validate_attrs(raw)
        if err:
            if is_ajax:
                return jsonify(success=False, error=err), 400
            return err, 400

        try:
            with open(USERS_FILE) as f:
                users = json.load(f)
        except Exception:
            users = {}

        # Create user with default password 'pass' and the specified attributes
        users[user_id] = {"attributes": attributes, "password": "pass"}
        try:
            with open(USERS_FILE, "w") as f:
                json.dump(users, f, indent=2)
                log_audit(
                    session.get("user_id"),
                    "add_user",
                    details=f"Added user {user_id} with attributes: {attributes}",
                    ip=request.remote_addr,
                )
                # Emit real-time update to admin dashboard
                socketio.emit(
                    "user_added",
                    {
                        "user": user_id,
                        "attributes": attributes,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    },
                    room="admin_updates",
                )
        except Exception as e:
            if is_ajax:
                return jsonify(success=False, error=f"could not save user: {e}"), 500
            return "Could not save user", 500

        if is_ajax:
            return jsonify(success=True)
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_add_user.html")


@app.route("/admin/edit_user/<user_id>", methods=["GET", "POST"])
def admin_edit_user(user_id):
    if session.get("user_id") != "admin":
        return redirect(url_for("home"))
    with open(USERS_FILE) as f:
        users = json.load(f)
    if request.method == "POST":
        # Detect AJAX/JSON requests and accept both form-encoded and JSON payloads
        is_ajax = (
            request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or request.is_json
            or "application/json" in request.headers.get("Accept", "")
        )

        attributes = []
        if request.is_json:
            data = request.get_json() or {}
            raw = data.get("attributes") or data.get("attrs") or ""
        else:
            raw = request.form.get("attributes", "")

        attributes, err = parse_and_validate_attrs(raw)
        if err:
            return jsonify(success=False, error=err), 400

        old_attrs = users.get(user_id, [])

        # Preserve the dictionary structure with password
        if isinstance(users.get(user_id), dict):
            # User exists as dictionary, update attributes but keep password
            existing_password = users[user_id].get("password", "pass")
            users[user_id] = {"attributes": attributes, "password": existing_password}
        else:
            # User exists as array (legacy format), convert to new format with default password
            users[user_id] = {"attributes": attributes, "password": "pass"}

        try:
            with open(USERS_FILE, "w") as f:
                json.dump(users, f, indent=2)
            log_audit(
                session.get("user_id"),
                "edit_user",
                details=f"Changed attributes for user {user_id} from {old_attrs} to {attributes}",
                ip=request.remote_addr,
            )
            # Emit real-time update to admin dashboard
            socketio.emit(
                "user_updated",
                {
                    "user": user_id,
                    "attributes": attributes,
                    "old_attributes": old_attrs,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                },
                room="admin_updates",
            )
        except Exception:
            if is_ajax:
                return jsonify(success=False, error="Could not save user"), 500
            return "Could not save user", 500

        if is_ajax:
            return jsonify(success=True)
        return redirect(url_for("admin_dashboard"))

    # Get user attributes, handling both dictionary and array formats
    user_data = users.get(user_id, [])
    if isinstance(user_data, dict):
        attrs = user_data.get("attributes", [])
    else:
        attrs = user_data
    attrs = ",".join(attrs)

    return render_template("admin_edit_user.html", user_id=user_id, attributes=attrs)


@app.route("/admin/delete_user/<user_id>")
def admin_delete_user(user_id):
    if session.get("user_id") != "admin":
        return redirect(url_for("home"))
    with open(USERS_FILE) as f:
        users = json.load(f)
    users.pop(user_id, None)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)
        log_audit(
            session.get("user_id"),
            "delete_user",
            details=f"Deleted user {user_id}",
            ip=request.remote_addr,
        )
    return redirect(url_for("admin_dashboard"))


# --- Admin Policy Management Routes ---
@app.route("/admin/add_policy", methods=["GET", "POST"])
def admin_add_policy():
    if session.get("user_id") != "admin":
        return redirect(url_for("home"))
    if request.method == "POST":
        file = request.form.get("file")
        policy = request.form.get("policy")
        with open(POLICIES_FILE) as f:
            policies = json.load(f)
        old_policy = policies.get(file, {}).get("policy", "")
        policies[file] = {"policy": policy}
        with open(POLICIES_FILE, "w") as f:
            json.dump(policies, f, indent=2)
        log_audit(
            session.get("user_id"),
            "add_policy",
            details=f"Added policy for file {file}: {policy}",
            ip=request.remote_addr,
        )
        # Emit real-time update to admin dashboard
        socketio.emit(
            "policy_added",
            {
                "file": file,
                "policy": policy,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            room="admin_updates",
        )
        return redirect(url_for("admin_dashboard"))
    else:
        return render_template("admin_add_policy.html")


@app.route("/admin/edit_policy/<file>", methods=["GET", "POST"])
def admin_edit_policy(file):
    if session.get("user_id") != "admin":
        return redirect(url_for("home"))
    with open(POLICIES_FILE) as f:
        policies = json.load(f)
    if request.method == "POST":
        policy = request.form.get("policy")
        # detect AJAX requests
        is_ajax = request.headers.get(
            "X-Requested-With"
        ) == "XMLHttpRequest" or "application/json" in request.headers.get("Accept", "")
        # basic validation
        if not policy or not policy.strip():
            if is_ajax:
                return jsonify(success=False, error="Policy is required"), 400
            return "Policy is required", 400

        old_policy = policies.get(file, {}).get("policy", "")
        policies[file] = {"policy": policy}
        # no longer support 'key' field; policies store only 'policy' and optional sender
        try:
            with open(POLICIES_FILE, "w") as f:
                json.dump(policies, f, indent=2)
            log_audit(
                session.get("user_id"),
                "edit_policy",
                details=f"Edited policy for file {file} from {old_policy} to {policy}",
                ip=request.remote_addr,
            )
            # Emit real-time update to admin dashboard
            socketio.emit(
                "policy_updated",
                {
                    "file": file,
                    "policy": policy,
                    "old_policy": old_policy,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                },
                room="admin_updates",
            )
        except Exception:
            if is_ajax:
                return jsonify(success=False, error="Could not save policy"), 500
            return "Could not save policy", 500

        if is_ajax:
            return jsonify(success=True)
        return redirect(url_for("admin_dashboard"))
    policy_val = policies.get(file, {}).get("policy", "")
    return render_template("admin_edit_policy.html", file=file, policy=policy_val)
    return render_template("admin_edit_policy.html", file=file, policy=policy_val)


@app.route("/admin/delete_policy/<file>")
def admin_delete_policy(file):
    if session.get("user_id") != "admin":
        return redirect(url_for("home"))
    with open(POLICIES_FILE) as f:
        policies = json.load(f)
    policies.pop(file, None)
    with open(POLICIES_FILE, "w") as f:
        json.dump(policies, f, indent=2)
        log_audit(
            session.get("user_id"),
            "delete_policy",
            details=f"Deleted policy for file {file}",
            ip=request.remote_addr,
        )
    return redirect(url_for("admin_dashboard"))


# AJAX endpoint: delete a single user (expects JSON { user: 'username' })
@app.route("/admin/delete_user", methods=["POST"])
def admin_delete_user_ajax():
    if session.get("user_id") != "admin":
        return jsonify(success=False, error="unauthorized"), 403
    data = request.get_json() or {}
    user = data.get("user")
    if not user:
        return jsonify(success=False, error="user required"), 400
    try:
        with open(USERS_FILE) as f:
            users = json.load(f)
    except Exception:
        users = {}

    deleted_user_data = users.get(user)
    users.pop(user, None)

    try:
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
        log_audit(
            session.get("user_id"),
            "delete_user",
            details=f"Deleted user {user}",
            ip=request.remote_addr,
        )
        # Emit real-time update to admin dashboard
        socketio.emit(
            "user_deleted",
            {"user": user, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
            room="admin_updates",
        )
    except Exception as e:
        return jsonify(success=False, error=f"could not update users: {e}"), 500
    return jsonify(success=True)


@app.route("/admin/delete_policy", methods=["POST"])
def admin_delete_policy_ajax():
    if session.get("user_id") != "admin":
        return jsonify(success=False, error="unauthorized"), 403
    data = request.get_json() or {}
    filename = data.get("file")
    if not filename:
        return jsonify(success=False, error="file required"), 400
    try:
        with open(POLICIES_FILE) as f:
            policies = json.load(f)
    except Exception:
        policies = {}
    policies.pop(filename, None)
    try:
        with open(POLICIES_FILE, "w") as f:
            json.dump(policies, f, indent=2)
        log_audit(
            session.get("user_id"),
            "delete_policy",
            details=f"Deleted policy for file {filename}",
            ip=request.remote_addr,
        )

        # Emit real-time update to admin dashboard
        socketio.emit(
            "policy_deleted",
            {
                "file": filename,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            room="admin_updates",
        )

        # Broadcast policy deletion - this affects file visibility
        socketio.emit(
            "file_deleted",
            {"deleter": session.get("user_id"), "filename": filename},
            room="dashboard_updates",
        )

    except Exception as e:
        return jsonify(success=False, error=f"could not update policies: {e}"), 500
    return jsonify(success=True)


# AJAX endpoint: delete an uploaded file and its policy (for users to delete their own files)
@app.route("/delete_file", methods=["POST"])
def delete_file():
    if "user_id" not in session:
        return jsonify(success=False, error="unauthorized"), 403

    user_id = session["user_id"]
    data = request.get_json() or {}
    filename = data.get("filename")
    if not filename:
        return jsonify(success=False, error="filename required"), 400

    # Check if user owns the file or is admin
    try:
        with open(POLICIES_FILE) as f:
            policies = json.load(f)
    except Exception:
        policies = {}

    policy_obj = policies.get(filename)
    if not policy_obj:
        return jsonify(success=False, error="file not found"), 404

    file_owner = policy_obj.get("sender") if isinstance(policy_obj, dict) else None

    # Allow deletion if user is the owner or admin
    if user_id != "admin" and file_owner != user_id:
        return (
            jsonify(
                success=False, error="unauthorized - you can only delete your own files"
            ),
            403,
        )

    # Remove file from uploads
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
        log_audit(
            user_id,
            "delete_file",
            details=f"Deleted file {filename}",
            ip=request.remote_addr,
        )
    except Exception as e:
        return jsonify(success=False, error=f"could not remove file: {e}"), 500

    # Remove policy entry if present
    if filename in policies:
        policies.pop(filename, None)
        try:
            with open(POLICIES_FILE, "w") as f:
                json.dump(policies, f, indent=2)
        except Exception as e:
            return jsonify(success=False, error=f"could not update policies: {e}"), 500

    # Broadcast file deletion to all connected dashboard users
    socketio.emit(
        "file_deleted",
        {"deleter": user_id, "filename": filename},
        room="dashboard_updates",
    )

    return jsonify(success=True)


# AJAX endpoint: delete an uploaded file and its policy (admin only)
@app.route("/admin/delete_file", methods=["POST"])
def admin_delete_file():
    if session.get("user_id") != "admin":
        return jsonify(success=False, error="unauthorized"), 403
    data = request.get_json() or {}
    filename = data.get("filename")
    if not filename:
        return jsonify(success=False, error="filename required"), 400

    # Remove file from uploads
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
        log_audit(
            session.get("user_id"),
            "delete_file",
            details=f"Deleted file {filename}",
            ip=request.remote_addr,
        )
    except Exception as e:
        return jsonify(success=False, error=f"could not remove file: {e}"), 500

    # Remove policy entry if present
    try:
        with open(POLICIES_FILE) as f:
            policies = json.load(f)
    except Exception:
        policies = {}

    if filename in policies:
        policies.pop(filename, None)
        try:
            with open(POLICIES_FILE, "w") as f:
                json.dump(policies, f, indent=2)
        except Exception as e:
            return jsonify(success=False, error=f"could not update policies: {e}"), 500

    # Broadcast file deletion to all connected dashboard users
    socketio.emit(
        "file_deleted",
        {"deleter": session.get("user_id"), "filename": filename},
        room="dashboard_updates",
    )

    return jsonify(success=True)


# AJAX endpoint: bulk delete users (expects JSON { users: [..] })
@app.route("/admin/bulk_delete_users", methods=["POST"])
def admin_bulk_delete_users():
    if session.get("user_id") != "admin":
        return jsonify(success=False, error="unauthorized"), 403
    data = request.get_json() or {}
    users_to_delete = data.get("users") or []
    if not isinstance(users_to_delete, list):
        return jsonify(success=False, error="users must be a list"), 400

    try:
        with open(USERS_FILE) as f:
            users = json.load(f)
    except Exception:
        users = {}

    for u in users_to_delete:
        users.pop(u, None)

    try:
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)

        # Log audit for each deleted user
        for u in users_to_delete:
            log_audit(
                session.get("user_id"),
                "bulk_delete_user",
                details=f"Bulk deleted user {u}",
                ip=request.remote_addr,
            )

        # Emit real-time update to admin dashboard
        socketio.emit(
            "users_bulk_deleted",
            {
                "users": users_to_delete,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            room="admin_updates",
        )

    except Exception as e:
        return jsonify(success=False, error=f"could not update users: {e}"), 500

    return jsonify(success=True)


# AJAX endpoint: bulk delete policies (expects JSON { files: [..] })
@app.route("/admin/bulk_delete_policies", methods=["POST"])
def admin_bulk_delete_policies():
    if session.get("user_id") != "admin":
        return jsonify(success=False, error="unauthorized"), 403
    data = request.get_json() or {}
    files_to_delete = data.get("files") or []
    if not isinstance(files_to_delete, list):
        return jsonify(success=False, error="files must be a list"), 400

    try:
        with open(POLICIES_FILE) as f:
            policies = json.load(f)
    except Exception:
        policies = {}

    for fname in files_to_delete:
        policies.pop(fname, None)

    try:
        with open(POLICIES_FILE, "w") as f:
            json.dump(policies, f, indent=2)

        # Log audit for each deleted policy
        for fname in files_to_delete:
            log_audit(
                session.get("user_id"),
                "bulk_delete_policy",
                details=f"Bulk deleted policy for file {fname}",
                ip=request.remote_addr,
            )

        # Emit real-time update to admin dashboard
        socketio.emit(
            "policies_bulk_deleted",
            {
                "files": files_to_delete,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            room="admin_updates",
        )

    except Exception as e:
        return jsonify(success=False, error=f"could not update policies: {e}"), 500

    return jsonify(success=True)


# AJAX endpoint: bulk set attributes for users (expects JSON { users: [...], attrs: 'a,b' })
@app.route("/admin/bulk_set_attrs", methods=["POST"])
def admin_bulk_set_attrs():
    if session.get("user_id") != "admin":
        return jsonify(success=False, error="unauthorized"), 403
    data = request.get_json() or {}
    users_to_update = data.get("users") or []
    attrs_raw = data.get("attrs") or ""
    if not isinstance(users_to_update, list):
        return jsonify(success=False, error="users must be a list"), 400

    # normalize attributes into a list
    attrs_list, err = parse_and_validate_attrs(attrs_raw)
    if err:
        return jsonify(success=False, error=err), 400

    try:
        with open(USERS_FILE) as f:
            users = json.load(f)
    except Exception:
        users = {}

    for u in users_to_update:
        old_attrs = users.get(u, [])
        users[u] = attrs_list
        log_audit(
            session.get("user_id"),
            "bulk_set_attrs",
            details=f"User {u}: attributes changed from {old_attrs} to {attrs_list}",
            ip=request.remote_addr,
        )

    try:
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)

        # Emit real-time update to admin dashboard
        socketio.emit(
            "users_bulk_attrs_updated",
            {
                "users": users_to_update,
                "attributes": attrs_list,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            room="admin_updates",
        )

    except Exception as e:
        return jsonify(success=False, error=f"could not update users: {e}"), 500

    return jsonify(success=True)


# WebSocket event handlers
@socketio.on("connect")
def handle_connect():
    user_id = session.get("user_id")
    if user_id:
        join_room(f"user_{user_id}")
        emit("connected", {"message": f"Connected as {user_id}"})


@socketio.on("disconnect")
def handle_disconnect():
    user_id = session.get("user_id")
    if user_id:
        leave_room(f"user_{user_id}")


@socketio.on("join_dashboard")
def handle_join_dashboard():
    user_id = session.get("user_id")
    if user_id:
        join_room("dashboard_updates")
        emit("joined_dashboard", {"message": "Joined dashboard updates"})


@socketio.on("leave_dashboard")
def handle_leave_dashboard():
    user_id = session.get("user_id")
    if user_id:
        leave_room("dashboard_updates")


@socketio.on("join_admin")
def handle_join_admin():
    user_id = session.get("user_id")
    if user_id == "admin":
        join_room("admin_updates")
        emit("joined_admin", {"message": "Joined admin updates"})


@socketio.on("leave_admin")
def handle_leave_admin():
    user_id = session.get("user_id")
    if user_id == "admin":
        leave_room("admin_updates")


if __name__ == "__main__":
    socketio.run(app, debug=False, port=7130, host="0.0.0.0")

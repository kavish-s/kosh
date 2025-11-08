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
import os
import json
from datetime import datetime, timedelta
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import time
from . import config
from . import utils


# Initialize Flask app
app = Flask(__name__, template_folder=config.TEMPLATES_DIR, static_folder=config.STATIC_DIR)
app.secret_key = config.SECRET_KEY
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Ensure required directories exist
config.ensure_directories()

# Initialize data files with defaults
utils.initialize_data_files()

# Register blueprints
app.register_blueprint(attribute_bp)


def cleanup_old_audit_logs():
    """
    Remove audit log entries older than retention period.
    This function runs periodically to maintain compliance with data retention policies.
    """
    try:
        if not os.path.exists(config.AUDIT_LOG_FILE):
            return
        
        cutoff_date = datetime.now() - timedelta(days=config.AUDIT_LOG_RETENTION_DAYS)
        temp_file = config.AUDIT_LOG_FILE + ".tmp"
        deleted_count = 0
        kept_count = 0
        
        with open(config.AUDIT_LOG_FILE, "r") as f_in, open(temp_file, "w") as f_out:
            for line in f_in:
                try:
                    entry = json.loads(line)
                    entry_time = datetime.strptime(entry.get("time", ""), "%Y-%m-%d %H:%M:%S")
                    
                    if entry_time >= cutoff_date:
                        f_out.write(line)
                        kept_count += 1
                    else:
                        deleted_count += 1
                except (json.JSONDecodeError, ValueError, KeyError):
                    # Keep malformed entries for investigation
                    f_out.write(line)
                    kept_count += 1
        
        # Replace original file with cleaned version
        os.replace(temp_file, config.AUDIT_LOG_FILE)
        
        if deleted_count > 0:
            print(f"[AUDIT CLEANUP] Deleted {deleted_count} old log entries, kept {kept_count} entries")
            # Log the cleanup action itself
            utils.log_audit(
                "system",
                "audit_cleanup",
                details=f"Deleted {deleted_count} audit entries older than {config.AUDIT_LOG_RETENTION_DAYS} days",
                ip="127.0.0.1",
                socketio=socketio
            )
    except Exception as e:
        print(f"[AUDIT CLEANUP] Error during cleanup: {e}")


def schedule_audit_cleanup():
    """
    Background thread to periodically clean up old audit logs.
    Runs every 24 hours.
    """
    while True:
        try:
            cleanup_old_audit_logs()
            # Sleep for 24 hours
            time.sleep(86400)
        except Exception as e:
            print(f"[AUDIT CLEANUP] Scheduler error: {e}")
            # Sleep for 1 hour before retrying on error
            time.sleep(3600)


@app.route("/")
def home():
    """Render the home/login page. Redirect to dashboard if already logged in."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    """
    Authenticate user and create session.
    
    POST data:
        user_id: Username
        password: User password
    
    Returns:
        Redirect to admin dashboard for admin user, regular dashboard for others
        Error message with 401/400 status on failure
    """
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
        with open(config.USERS_FILE) as f:
            users = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return "System error: Unable to load user data", 500

    # Verify user exists
    if user_id in users:
        expected_hash = (
            users[user_id].get("password") if isinstance(users[user_id], dict) else None
        )
        if expected_hash and check_password_hash(expected_hash, password):
            # Set session for admin or regular users
            session["user_id"] = user_id
            # Log login event
            utils.log_audit(
                user_id, "login", details="Login successful", ip=request.remote_addr, socketio=socketio
            )
            if user_id == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))
        else:
            utils.log_audit(
                user_id,
                "login_failed",
                details="Invalid password",
                ip=request.remote_addr,
            )
            return "Invalid password", 401
    utils.log_audit(user_id, "login_failed", details="Invalid user", ip=request.remote_addr)
    return "Invalid user", 401


@app.route("/dashboard")
def dashboard():
    """
    Render user dashboard with accessible files and permissions.
    
    Shows:
        - Files accessible to user based on attributes
        - Attribute management interface
        - Role manager interface (if user has role_manager permission)
        - Upload and file management tools
    """
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("home"))

    # Get user files using the helper function
    policies = utils.safe_load_json(config.POLICIES_FILE, {})
    user_files = utils.get_user_files(user_id, policies, abe)

    # Get local IP address for share info
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        server_ip = s.getsockname()[0]
        s.close()
    except Exception:
        server_ip = "localhost"

    # Load all attributes for attribute selection UI
    all_attributes = utils.load_all_attributes()
    
    # Check if user has role_manager permission
    is_role_manager = utils.has_role(user_id, "role_manager")
    
    # Load additional data for role managers
    role_manager_data = {}
    if is_role_manager:
        try:
            with open(config.USERS_FILE) as f:
                role_manager_data['users'] = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            role_manager_data['users'] = {}
        
        try:
            with open(config.POLICIES_FILE) as f:
                role_manager_data['policies'] = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            role_manager_data['policies'] = {}
        
        # Load audit logs
        audit_logs = []
        try:
            with open(config.AUDIT_LOG_FILE) as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        audit_logs.append(entry)
                    except json.JSONDecodeError:
                        continue
        except (IOError, OSError):
            audit_logs = []
        role_manager_data['audit_logs'] = list(reversed(audit_logs))
        role_manager_data['all_attributes'] = all_attributes
    
    return render_template(
        "dashboard.html",
        user_id=user_id,
        files=user_files,
        server_ip=server_ip,
        all_attributes=all_attributes,
        is_role_manager=is_role_manager,
        role_manager_data=role_manager_data
    )


@app.route("/api/files")
def api_files():
    """
    API endpoint to get updated file list for current user.
    
    Returns:
        JSON with list of files accessible to the user
    """
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    policies = utils.safe_load_json(config.POLICIES_FILE, {})
    user_files = utils.get_user_files(user_id, policies, abe)
    return jsonify({"files": user_files})


@app.route("/change_password", methods=["POST"])
def change_password():
    """
    Allow user to change their password.
    
    POST data:
        new_password: New password (minimum 6 characters)
    
    Returns:
        Redirect to dashboard with flash message
    """
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
        with open(config.USERS_FILE) as f:
            users = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        flash("System error: Unable to load user data")
        return redirect(url_for("dashboard"))

    if user_id in users:
        # Update password for existing user
        user_data = utils.normalize_user_data(users[user_id])
        user_data["password"] = generate_password_hash(new_password)
        users[user_id] = user_data
        
        try:
            with open(config.USERS_FILE, "w") as f:
                json.dump(users, f, indent=2)
            utils.log_audit(
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
    """
    Handle file upload with encryption and policy assignment.
    
    POST data:
        file: One or more files to upload
        policy: Attribute-based access policy (comma-separated attributes)
    
    Security:
        - Files are encrypted with AES-CTR and HMAC-SHA256
        - File type and size validation
        - Secure filename handling
    
    Returns:
        JSON with success status and uploaded filenames
    """
    if "user_id" not in session:
        return jsonify(success=False, error="Not authenticated"), 401

    files = request.files.getlist("file")
    policy = request.form.get("policy", "")

    # Input validation
    if not files or all(not file.filename for file in files):
        return jsonify(success=False, error="No files selected"), 400

    # Validate file types and sizes
    allowed_extensions = {
        'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'csv',
        'jpg', 'jpeg', 'png', 'gif', 'zip', 'rar', 'py', 'js', 'json',
        'mp4', 'mov', 'avi', 'mkv'
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
        policies = utils.safe_load_json(config.POLICIES_FILE, {})
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

            filepath = os.path.join(config.UPLOAD_FOLDER, filename)

            # Encrypt and save file
            with open(filepath, "wb") as f_out:
                aes.encrypt(file.stream, f_out)

            policies[filename] = {"policy": policy, "sender": session["user_id"]}
            uploaded_files.append(filename)

            # Log upload event for each file
            utils.log_audit(
                session["user_id"],
                "upload",
                details=f"Uploaded {original_filename}",
                ip=request.remote_addr,
            )

        except Exception as e:
            # Clean up any partially uploaded files
            for uploaded_file in uploaded_files:
                try:
                    os.remove(os.path.join(config.UPLOAD_FOLDER, uploaded_file))
                except:
                    pass
            return jsonify(success=False, error=f"Upload failed: {str(e)}"), 500

    try:
        with open(config.POLICIES_FILE, "w") as f:
            json.dump(policies, f, indent=2)
    except IOError:
        return (
            jsonify(success=False, error="System error: Unable to save policies"),
            500,
        )

    # Broadcast file update to all connected dashboard users
    socketio.emit('file_uploaded', {
        'uploader': session['user_id'],
        'files': uploaded_files
    }, room='dashboard_updates')
    
    # Emit file updates to admin dashboard
    for filename in uploaded_files:
        file_stats = {
            'name': filename,
            'owner': session['user_id'],
            'upload_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'size': 'Unknown'
        }
        try:
            file_path = os.path.join(config.UPLOAD_FOLDER, filename)
            if os.path.exists(file_path):
                file_stats['size'] = f"{os.path.getsize(file_path)} bytes"
        except:
            pass
            
        utils.emit_socketio_event(
            socketio,
            'file_uploaded',
            {'file': file_stats},
        )

    return jsonify(success=True, filenames=uploaded_files)


@app.route("/download/<filename>")
def download(filename):
    """
    Download and decrypt a file if user has access.
    
    Args:
        filename: Name of the encrypted file
    
    Security:
        - Prevents directory traversal attacks
        - Validates user access based on attributes or ownership
        - Verifies HMAC before decryption
        - Logs all download attempts
    
    Returns:
        Decrypted file or error response
    """
    import traceback
    print(f"[DOWNLOAD] User session: {session.get('user_id')}, filename: {filename}")
    if 'user_id' not in session:
        print("[DOWNLOAD] No user session, redirecting to home.")
        return redirect(url_for('home'))

    user_id = session['user_id']

    # Input validation and sanitization
    if not filename:
        print("[DOWNLOAD] Invalid filename: empty.")
        return "Invalid filename", 400

    # Prevent directory traversal attacks
    filename = os.path.basename(filename)
    if not filename or filename in ['.', '..'] or '/' in filename or '\\' in filename:
        print(f"[DOWNLOAD] Invalid filename after sanitization: {filename}")
        return "Invalid filename", 400

    # Ensure filename has .enc extension for security
    if not filename.endswith('.enc'):
        print(f"[DOWNLOAD] Filename does not end with .enc: {filename}")
        return "Access Denied", 403

    try:
        policies = utils.safe_load_json(config.POLICIES_FILE, {})
        print(f"[DOWNLOAD] Loaded policies for {filename}: {policies.get(filename)}")
        policy_obj = policies.get(filename)
        if not policy_obj:
            print(f"[DOWNLOAD] No policy found for {filename}")
            return "Access Denied", 403
        access_policy = policy_obj.get('policy') if isinstance(policy_obj, dict) else policy_obj
        sender = policy_obj.get('sender') if isinstance(policy_obj, dict) else None
        # Owners can always download their own files
        if sender == user_id:
            print(f"[DOWNLOAD] User {user_id} is owner of {filename}")
        else:
            if isinstance(access_policy, str):
                required_attrs = [a.strip() for a in access_policy.split(',') if a.strip()]
            elif isinstance(access_policy, list):
                required_attrs = access_policy
            else:
                required_attrs = []
            print(f"[DOWNLOAD] Required attributes for {filename}: {required_attrs}")
            if not abe.check_access(user_id, required_attrs):
                print(f"[DOWNLOAD] User {user_id} does not satisfy required attributes for {filename}")
                return "Access Denied", 403
    except Exception as e:
        print(f"[DOWNLOAD] Error checking access for {filename}: {e}")
        traceback.print_exc()
        return "Access Denied", 403

    encrypted_path = os.path.join(config.UPLOAD_FOLDER, filename)
    decrypted_stream = BytesIO()

    try:
        with open(encrypted_path, 'rb') as f_in:
            print(f"[DOWNLOAD] Decrypting file {encrypted_path}")
            aes.decrypt(f_in, decrypted_stream)
    except FileNotFoundError:
        print(f"[DOWNLOAD] File not found: {encrypted_path}")
        return "File not found", 404
    except ValueError as e:
        # This will catch HMAC verification errors
        print(f"[DOWNLOAD] Decryption or verification failed for {filename}: {e}")
        traceback.print_exc()
        return "Access Denied: File is corrupt or has been tampered with.", 403
    except Exception as e:
        print(f"[DOWNLOAD] Unexpected error during decryption for {filename}: {e}")
        traceback.print_exc()
        return "System error: Unable to process file", 500

    # Log download event
    print(f"[DOWNLOAD] Logging download event for user {user_id} and file {filename}")
    utils.log_audit(session['user_id'], 'download', details=f'Downloaded {filename}', ip=request.remote_addr)

    decrypted_stream.seek(0)
    original_name = filename.replace(".enc", "")
    print(f"[DOWNLOAD] Sending file {original_name} to user {user_id}")
    return send_file(decrypted_stream, download_name=original_name, as_attachment=True)


@app.route("/logout")
def logout():
    """Clear session and redirect to home page."""
    user_id = session.get("user_id")
    if user_id:
        utils.log_audit(user_id, "logout", details="User logged out", ip=request.remote_addr)
    session.clear()
    return redirect(url_for("home"))


@app.route("/admin")
def admin_dashboard():
    """
    Admin dashboard with full system overview.
    
    Admin-only features:
        - View and manage all users
        - View and manage all policies
        - View all files regardless of access policy
        - View and download audit logs
        - Manage global attributes
    """
    if session.get("user_id") != "admin":
        return redirect(url_for("home"))

    # Load users and policies with error handling
    try:
        with open(config.USERS_FILE) as f:
            users = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        users = {}

    try:
        with open(config.POLICIES_FILE) as f:
            policies = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        policies = {}

    # Admin sees all files, regardless of policy
    all_files = []
    try:
        for fname in os.listdir(config.UPLOAD_FOLDER):
            fpath = os.path.join(config.UPLOAD_FOLDER, fname)
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
        with open(config.AUDIT_LOG_FILE) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    audit_logs.append(entry)
                except json.JSONDecodeError:
                    continue
    except (IOError, OSError):
        audit_logs = []
    audit_logs = list(reversed(audit_logs))  # latest first

    # Load global attribute list
    all_attributes = utils.load_all_attributes()
    
    # Save updated attributes if needed
    utils.save_all_attributes(all_attributes)

    return render_template(
        "admin.html",
        users=users,
        policies=policies,
        all_files=all_files,
        audit_logs=audit_logs,
        all_attributes=all_attributes,
    )


@app.route("/admin/add_user", methods=["GET", "POST"])
def admin_add_user():
    """
    Add a new user with attributes (admin only).
    
    POST data (JSON):
        user or user_id: Username
        attrs or attributes: Comma-separated attribute list
    
    Returns:
        JSON response with success status
    """
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

        attributes, err = utils.parse_and_validate_attrs(raw)
        if err:
            return jsonify(success=False, error=err), 400

        try:
            with open(config.USERS_FILE) as f:
                users = json.load(f)
        except Exception:
            users = {}

        # Create user with attributes, default password, and empty roles
        users[user_id] = {
            "attributes": attributes, 
            "password": generate_password_hash("pass"), 
            "roles": []
        }
        try:
            with open(config.USERS_FILE, "w") as f:
                json.dump(users, f, indent=2)
                utils.log_audit(
                    session.get("user_id"),
                    "add_user",
                    details=f"Added user {user_id} with attributes: {attributes}",
                    ip=request.remote_addr,
                )
                # Emit real-time update to admin dashboard
                utils.emit_socketio_event(
                    socketio,
                    "user_added",
                    {
                        "user": user_id,
                        "attributes": attributes,
                        "roles": [],
                    },
                )
        except Exception as e:
            return jsonify(success=False, error=f"could not save user: {e}"), 500

        return jsonify(success=True)


@app.route("/admin/update_user_roles", methods=["POST"])
def admin_update_user_roles():
    """
    Update roles for a specific user (admin only).
    
    POST data (JSON):
        user: Username
        roles: List of role names
    
    Available roles:
        - role_manager: Can manage user attributes
    
    Returns:
        JSON response with success status
    """
    if session.get("user_id") != "admin":
        return jsonify(success=False, error="unauthorized"), 403
    
    data = request.get_json() or {}
    target_user = data.get("user")
    roles = data.get("roles", [])
    
    if not target_user:
        return jsonify(success=False, error="user required"), 400
    
    if not isinstance(roles, list):
        return jsonify(success=False, error="roles must be a list"), 400
    
    # Validate roles
    valid_roles = ["role_manager"]
    for role in roles:
        if role not in valid_roles:
            return jsonify(success=False, error=f"Invalid role: {role}"), 400
    
    try:
        with open(config.USERS_FILE) as f:
            users = json.load(f)
    except Exception:
        return jsonify(success=False, error="could not load users"), 500
    
    if target_user not in users:
        return jsonify(success=False, error="user not found"), 404
    
    # Normalize user data to dict format
    user_data = utils.normalize_user_data(users[target_user])
    old_roles = user_data.get("roles", [])
    user_data["roles"] = roles
    users[target_user] = user_data
    
    try:
        with open(config.USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
        
        utils.log_audit(
            session.get("user_id"),
            "update_user_roles",
            details=f"Updated roles for {target_user} from {old_roles} to {roles}",
            ip=request.remote_addr,
        )
        
        # Emit real-time update to admin dashboard
        utils.emit_socketio_event(
            socketio,
            "user_roles_updated",
            {
                "user": target_user,
                "roles": roles,
                "old_roles": old_roles,
            },
        )
        
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=f"could not save roles: {e}"), 500


@app.route("/admin/edit_user/<user_id>", methods=["GET", "POST"])
def admin_edit_user(user_id):
    if session.get("user_id") != "admin":
        return redirect(url_for("home"))
    with open(config.USERS_FILE) as f:
        users = json.load(f)
    if request.method == "POST":
        # Detect AJAX/JSON requests and accept both form-encoded and JSON payloads
        is_ajax = (
            request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or request.is_json
            or "application/json" in request.headers.get("Accept", "")
        )

        if request.is_json:
            data = request.get_json() or {}
            raw = data.get("attributes") or data.get("attrs") or ""
        else:
            raw = request.form.get("attributes", "")

        attributes, err = utils.parse_and_validate_attrs(raw)
        if err:
            return jsonify(success=False, error=err), 400

        # Normalize user data and preserve password
        user_data = utils.normalize_user_data(users.get(user_id))
        old_attrs = user_data.get("attributes", [])
        user_data["attributes"] = attributes
        users[user_id] = user_data

        try:
            with open(config.USERS_FILE, "w") as f:
                json.dump(users, f, indent=2)
            utils.log_audit(
                session.get("user_id"),
                "edit_user",
                details=f"Changed attributes for user {user_id} from {old_attrs} to {attributes}",
                ip=request.remote_addr,
            )
            # Emit real-time update to admin dashboard
            utils.emit_socketio_event(
                socketio,
                "user_updated",
                {
                    "user": user_id,
                    "attributes": attributes,
                    "old_attributes": old_attrs,
                },
            )
        except Exception:
            if is_ajax:
                return jsonify(success=False, error="Could not save user"), 500
            return "Could not save user", 500

        if is_ajax:
            return jsonify(success=True)
        return redirect(url_for("admin_dashboard"))

    # Get user attributes for display
    user_data = utils.normalize_user_data(users.get(user_id, {}))
    attrs = ",".join(user_data.get("attributes", []))

    return render_template("admin_edit_user.html", user_id=user_id, attributes=attrs)


@app.route("/admin/delete_user/<user_id>")
def admin_delete_user(user_id):
    if session.get("user_id") != "admin":
        return redirect(url_for("home"))
    with open(config.USERS_FILE) as f:
        users = json.load(f)
    users.pop(user_id, None)
    with open(config.USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)
        utils.log_audit(
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
        with open(config.POLICIES_FILE) as f:
            policies = json.load(f)
        old_policy = policies.get(file, {}).get("policy", "")
        policies[file] = {"policy": policy}
        with open(config.POLICIES_FILE, "w") as f:
            json.dump(policies, f, indent=2)
        utils.log_audit(
            session.get("user_id"),
            "add_policy",
            details=f"Added policy for file {file}: {policy}",
            ip=request.remote_addr,
        )
        # Emit real-time update to admin dashboard
        utils.emit_socketio_event(
            socketio,
            'policy_added',
            {'file': file, 'policy': {"policy": policy, "key": None}},
        )
        return redirect(url_for('admin_dashboard'))
    else:
        return render_template("admin_add_policy.html")


@app.route("/admin/edit_policy/<file>", methods=["GET", "POST"])
def admin_edit_policy(file):
    if session.get("user_id") != "admin":
        return redirect(url_for("home"))
    with open(config.POLICIES_FILE) as f:
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
            with open(config.POLICIES_FILE, "w") as f:
                json.dump(policies, f, indent=2)
            utils.log_audit(
                session.get("user_id"),
                "edit_policy",
                details=f"Edited policy for file {file} from {old_policy} to {policy}",
                ip=request.remote_addr,
            )
            # Emit real-time update to admin dashboard
            utils.emit_socketio_event(
                socketio,
                'policy_updated',
                {
                    'file': file,
                    'policy': {"policy": policy, "key": None},
                    'old_policy': old_policy,
                },
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


@app.route("/admin/delete_policy/<file>")
def admin_delete_policy(file):
    if session.get("user_id") != "admin":
        return redirect(url_for("home"))
    with open(config.POLICIES_FILE) as f:
        policies = json.load(f)
    policies.pop(file, None)
    with open(config.POLICIES_FILE, "w") as f:
        json.dump(policies, f, indent=2)
    utils.log_audit(session.get('user_id'), 'delete_policy', details=f'Deleted policy for file {file}', ip=request.remote_addr)
    
    # Emit real-time update to admin dashboard
    utils.emit_socketio_event(
        socketio,
        'policy_deleted',
        {'file': file},
    )
    
    return redirect(url_for('admin_dashboard'))


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
        with open(config.USERS_FILE) as f:
            users = json.load(f)
    except Exception:
        users = {}

    deleted_user_data = users.get(user)
    users.pop(user, None)

    try:
        with open(config.USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
        utils.log_audit(
            session.get("user_id"),
            "delete_user",
            details=f"Deleted user {user}",
            ip=request.remote_addr,
        )
        # Emit real-time update to admin dashboard
        utils.emit_socketio_event(
            socketio,
            "user_deleted",
            {"user": user},
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
        with open(config.POLICIES_FILE) as f:
            policies = json.load(f)
    except Exception:
        policies = {}
    policies.pop(filename, None)
    try:
        with open(config.POLICIES_FILE, "w") as f:
            json.dump(policies, f, indent=2)
        utils.log_audit(
            session.get("user_id"),
            "delete_policy",
            details=f"Deleted policy for file {filename}",
            ip=request.remote_addr,
        )

        # Emit real-time update to admin dashboard
        utils.emit_socketio_event(
            socketio,
            "policy_deleted",
            {"file": filename},
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


@app.route("/delete_file", methods=["POST"])
def delete_file():
    """Delete a file (user can only delete their own files, admin can delete any)."""
    if "user_id" not in session:
        return jsonify(success=False, error="unauthorized"), 403

    user_id = session["user_id"]
    data = request.get_json() or {}
    filename = data.get("filename")
    
    if not filename:
        return jsonify(success=False, error="filename required"), 400

    # Check if user owns the file or is admin
    try:
        with open(config.POLICIES_FILE) as f:
            policies = json.load(f)
    except Exception:
        policies = {}

    policy_obj = policies.get(filename)
    if not policy_obj:
        return jsonify(success=False, error="file not found"), 404

    file_owner = policy_obj.get("sender") if isinstance(policy_obj, dict) else None

    # Allow deletion if user is the owner or admin
    if user_id != "admin" and file_owner != user_id:
        return jsonify(success=False, error="unauthorized - you can only delete your own files"), 403

    # Use helper function to delete file and policy
    success, error = utils.delete_file_and_policy(filename, user_id, request.remote_addr, socketio)
    
    if success:
        return jsonify(success=True)
    else:
        return jsonify(success=False, error=error), 500


@app.route("/admin/delete_file", methods=["POST"])
def admin_delete_file():
    """Delete a file (admin only)."""
    if session.get("user_id") != "admin":
        return jsonify(success=False, error="unauthorized"), 403
    
    data = request.get_json() or {}
    filename = data.get("filename")
    
    if not filename:
        return jsonify(success=False, error="filename required"), 400

    # Use helper function to delete file and policy
    success, error = utils.delete_file_and_policy(filename, session.get("user_id"), request.remote_addr, socketio)
    
    if success:
        return jsonify(success=True)
    else:
        return jsonify(success=False, error=error), 500



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
        with open(config.USERS_FILE) as f:
            users = json.load(f)
    except Exception:
        users = {}

    for u in users_to_delete:
        users.pop(u, None)

    try:
        with open(config.USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)

        # Log audit for each deleted user
        for u in users_to_delete:
            utils.log_audit(
                session.get("user_id"),
                "bulk_delete_user",
                details=f"Bulk deleted user {u}",
                ip=request.remote_addr,
            )

        # Emit real-time update to admin dashboard
        utils.emit_socketio_event(
            socketio,
            "users_bulk_deleted",
            {"users": users_to_delete},
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
        with open(config.POLICIES_FILE) as f:
            policies = json.load(f)
    except Exception:
        policies = {}

    for fname in files_to_delete:
        policies.pop(fname, None)

    try:
        with open(config.POLICIES_FILE, "w") as f:
            json.dump(policies, f, indent=2)

        # Log audit for each deleted policy
        for fname in files_to_delete:
            utils.log_audit(
                session.get("user_id"),
                "bulk_delete_policy",
                details=f"Bulk deleted policy for file {fname}",
                ip=request.remote_addr,
            )

        # Emit real-time update to admin dashboard
        utils.emit_socketio_event(
            socketio,
            "policies_bulk_deleted",
            {"files": files_to_delete},
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
    attrs_list, err = utils.parse_and_validate_attrs(attrs_raw)
    if err:
        return jsonify(success=False, error=err), 400

    try:
        with open(config.USERS_FILE) as f:
            users = json.load(f)
    except Exception:
        users = {}

    for u in users_to_update:
        old_attrs = users.get(u, [])
        users[u] = attrs_list
        utils.log_audit(
            session.get("user_id"),
            "bulk_set_attrs",
            details=f"User {u}: attributes changed from {old_attrs} to {attrs_list}",
            ip=request.remote_addr,
        )

    try:
        with open(config.USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)

        # Emit real-time update to admin dashboard
        utils.emit_socketio_event(
            socketio,
            "users_bulk_attrs_updated",
            {
                "users": users_to_update,
                "attributes": attrs_list,
            },
        )

    except Exception as e:
        return jsonify(success=False, error=f"could not update users: {e}"), 500

    return jsonify(success=True)


# WebSocket event handlers
@socketio.on("connect")
def handle_connect():
    """Handle WebSocket connection - join user-specific room."""
    user_id = session.get("user_id")
    if user_id:
        join_room(f"user_{user_id}")
        emit("connected", {"message": f"Connected as {user_id}"})


@socketio.on("disconnect")
def handle_disconnect():
    """Handle WebSocket disconnection - leave user-specific room."""
    user_id = session.get("user_id")
    if user_id:
        leave_room(f"user_{user_id}")


@socketio.on("join_dashboard")
def handle_join_dashboard():
    """Join dashboard updates room for real-time file notifications."""
    user_id = session.get("user_id")
    if user_id:
        join_room("dashboard_updates")
        emit("joined_dashboard", {"message": "Joined dashboard updates"})


@socketio.on("leave_dashboard")
def handle_leave_dashboard():
    """Leave dashboard updates room."""
    user_id = session.get("user_id")
    if user_id:
        leave_room("dashboard_updates")


@socketio.on("join_admin")
def handle_join_admin():
    """Join admin updates room for real-time admin notifications (admin only)."""
    user_id = session.get("user_id")
    if user_id == "admin":
        join_room("admin_updates")
        emit("joined_admin", {"message": "Joined admin updates"})


@socketio.on("leave_admin")
def handle_leave_admin():
    """Leave admin updates room."""
    user_id = session.get("user_id")
    if user_id == "admin":
        leave_room("admin_updates")


@app.route("/admin/download_audit_logs", methods=["GET"])
def download_audit_logs():
    """
    Download audit logs as a JSON file (admin only).
    Implements security best practices:
    - Admin-only access
    - Optional date range filtering
    - Sanitized filename with timestamp
    - Proper content-type headers
    """
    if session.get("user_id") != "admin":
        return jsonify(success=False, error="unauthorized"), 403
    
    try:
        # Get optional date range parameters
        from_date = request.args.get("from")
        to_date = request.args.get("to")
        
        logs = []
        
        if not os.path.exists(config.AUDIT_LOG_FILE):
            # Return empty logs if file doesn't exist
            logs_data = []
        else:
            with open(config.AUDIT_LOG_FILE, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        
                        # Apply date filtering if specified
                        if from_date or to_date:
                            try:
                                entry_time = datetime.strptime(entry.get("time", ""), "%Y-%m-%d %H:%M:%S")
                                
                                if from_date:
                                    from_datetime = datetime.strptime(from_date, "%Y-%m-%d")
                                    if entry_time < from_datetime:
                                        continue
                                
                                if to_date:
                                    to_datetime = datetime.strptime(to_date, "%Y-%m-%d")
                                    # Make to_date inclusive
                                    to_datetime = to_datetime + timedelta(days=1)
                                    if entry_time >= to_datetime:
                                        continue
                            except (ValueError, KeyError):
                                # Include entries with invalid dates
                                pass
                        
                        logs.append(entry)
                    except json.JSONDecodeError:
                        # Skip malformed entries
                        continue
            
            logs_data = logs
        
        # Create JSON file in memory
        logs_json = json.dumps(logs_data, indent=2)
        logs_bytes = BytesIO(logs_json.encode('utf-8'))
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_logs_{timestamp}.json"
        
        # Log the download action
        utils.log_audit(
            session.get("user_id"),
            "download_audit_logs",
            details=f"Downloaded {len(logs_data)} audit log entries",
            ip=request.remote_addr
        )
        
        # Send file with proper headers
        return send_file(
            logs_bytes,
            mimetype="application/json",
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        print(f"[AUDIT DOWNLOAD] Error: {e}")
        return jsonify(success=False, error="Failed to download audit logs"), 500



if __name__ == "__main__":
    # Start the audit log cleanup thread
    cleanup_thread = threading.Thread(target=schedule_audit_cleanup, daemon=True)
    cleanup_thread.start()
    print(f"[AUDIT CLEANUP] Started background cleanup task (retention: {config.AUDIT_LOG_RETENTION_DAYS} days)")
    import eventlet
    import eventlet.wsgi
    print(f"[SERVER] Starting server on {config.HOST}:{config.PORT}")
    socketio.run(app, debug=config.DEBUG, port=config.PORT, host=config.HOST)

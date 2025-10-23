"""
Utility functions for Kosh application.
Contains shared helper functions used across the application.
"""
import os
import json
import re
from datetime import datetime
from werkzeug.security import generate_password_hash
from . import config


def safe_load_json(file_path, default_value=None):
    """
    Safely load JSON from a file, handling empty files and JSON decode errors.
    
    Args:
        file_path: Path to the JSON file
        default_value: Value to return and save if file is missing or corrupted
    
    Returns:
        Loaded JSON data or default_value
    """
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        if default_value is None:
            default_value = {}
        with open(file_path, "w") as f:
            json.dump(default_value, f)
        return default_value


def parse_and_validate_attrs(raw):
    """
    Normalize raw attributes input into a deduplicated list and validate format.
    
    Args:
        raw: Attributes as a list or comma-separated string
    
    Returns:
        tuple: (attrs_list, error_message) - error_message is None if successful
    """
    if raw is None:
        return [], None
    
    if isinstance(raw, list):
        tokens = [str(x).strip() for x in raw if str(x).strip()]
    elif isinstance(raw, str):
        tokens = [t.strip() for t in raw.split(",") if t.strip()]
    else:
        return None, "Invalid attributes format"

    # Validate tokens (alphanumeric, underscore, dash only)
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


def log_audit(user, action, details=None, ip=None, socketio=None):
    """
    Log audit events with proper error handling.
    
    Args:
        user: Username performing the action
        action: Type of action being performed
        details: Additional details about the action
        ip: IP address of the user
        socketio: SocketIO instance for real-time updates (optional)
    """
    try:
        entry = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "user": str(user) if user else "unknown",
            "action": str(action) if action else "unknown",
            "details": str(details) if details else "",
            "ip": str(ip) if ip else "",
        }

        with open(config.AUDIT_LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

        # Emit real-time audit log update to admin dashboard
        if socketio:
            socketio.emit("audit_log_added", entry, room="admin_updates")

    except Exception as e:
        # Log to console if audit logging fails
        print(f"Audit logging failed: {e}")


def has_role(user_id, role):
    """
    Check if a user has a specific role.
    
    Args:
        user_id: Username to check
        role: Role name to check for
    
    Returns:
        bool: True if user has the role or is admin
    """
    try:
        with open(config.USERS_FILE) as f:
            users = json.load(f)
        user_data = users.get(user_id)
        if isinstance(user_data, dict):
            roles = user_data.get("roles", [])
            return role in roles or "admin" in roles
        return False
    except Exception:
        return False


def initialize_data_files():
    """
    Initialize default data files if they don't exist.
    Creates users.json with default users and policies.json as empty.
    """
    # Initialize users file with default admin and sample users
    if not os.path.exists(config.USERS_FILE):
        with open(config.USERS_FILE, "w") as f:
            json.dump(
                {
                    "admin": {
                        "attributes": ["admin"],
                        "password": generate_password_hash(config.DEFAULT_PASSWORD),
                        "roles": ["admin"]
                    },
                    "user1": {
                        "attributes": ["student", "year3"],
                        "password": generate_password_hash(config.DEFAULT_PASSWORD),
                        "roles": []
                    },
                    "user2": {
                        "attributes": ["faculty"],
                        "password": generate_password_hash(config.DEFAULT_PASSWORD),
                        "roles": []
                    },
                },
                f,
                indent=2
            )

    # Initialize policies file
    if not os.path.exists(config.POLICIES_FILE):
        with open(config.POLICIES_FILE, "w") as f:
            json.dump({}, f)
    
    # Initialize attributes file
    if not os.path.exists(config.ATTRIBUTES_FILE):
        with open(config.ATTRIBUTES_FILE, "w") as f:
            json.dump(["admin", "student", "faculty", "year3"], f, indent=2)


def validate_file_upload(file, allowed_extensions=None, max_size=None):
    """
    Validate uploaded file for security and size constraints.
    
    Args:
        file: FileStorage object from Flask
        allowed_extensions: Set of allowed file extensions (uses config default if None)
        max_size: Maximum file size in bytes (uses config default if None)
    
    Returns:
        tuple: (is_valid, error_message) - error_message is None if valid
    """
    if allowed_extensions is None:
        allowed_extensions = config.ALLOWED_EXTENSIONS
    if max_size is None:
        max_size = config.MAX_FILE_SIZE
    
    if not file.filename:
        return False, "No file selected"
    
    # Check file extension
    if "." in file.filename:
        ext = file.filename.rsplit(".", 1)[1].lower()
        if ext not in allowed_extensions:
            return False, f"File type .{ext} not allowed"
    
    # Check file size
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    
    if size > max_size:
        return False, f"File {file.filename} is too large (max {max_size // (1024*1024)}MB)"
    
    return True, None


def get_user_files(user_id, policies, abe_module):
    """
    Get list of files accessible to a user based on their attributes and ownership.
    
    Args:
        user_id: Username to check access for
        policies: Dictionary of file policies
        abe_module: ABE simulator module for access checking
    
    Returns:
        list: List of file dictionaries with filename, sender, and is_owner fields
    """
    user_files = []
    is_admin = user_id == "admin"

    if is_admin:
        # Admin sees all files
        for fname, policy in policies.items():
            if isinstance(policy, dict):
                sender = policy.get("sender")
            else:
                sender = None
            user_files.append({
                "filename": fname,
                "sender": sender,
                "is_owner": True,  # Admin can delete any file
            })
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
                    has_access = abe_module.check_access(user_id, required_attrs)
                except Exception:
                    has_access = False

            if has_access:
                user_files.append({
                    "filename": fname,
                    "sender": sender,
                    "is_owner": is_owner
                })

    return user_files

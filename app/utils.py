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


def normalize_user_data(user_data):
    """
    Convert legacy user format (list of attributes) to new format (dict with attributes and password).
    
    Args:
        user_data: User data in any format (dict, list, or other)
    
    Returns:
        dict: Normalized user data with 'attributes', 'password', and 'roles' fields
    """
    from werkzeug.security import generate_password_hash
    
    if isinstance(user_data, dict):
        # Already in new format, ensure all fields exist
        return {
            'attributes': user_data.get('attributes', []),
            'password': user_data.get('password', generate_password_hash('pass')),
            'roles': user_data.get('roles', [])
        }
    elif isinstance(user_data, list):
        # Legacy format: list of attributes
        return {
            'attributes': user_data,
            'password': generate_password_hash('pass'),
            'roles': []
        }
    else:
        # Unknown format: return default
        return {
            'attributes': [],
            'password': generate_password_hash('pass'),
            'roles': []
        }


def get_user_attributes(user_data):
    """
    Extract attributes from user data in any format.
    
    Args:
        user_data: User data in any format (dict, list, or other)
    
    Returns:
        list: List of attribute strings
    """
    if isinstance(user_data, dict):
        return user_data.get('attributes', [])
    elif isinstance(user_data, list):
        return user_data
    else:
        return []


def load_all_attributes():
    """
    Load and merge attributes from both users.json and attributes.json.
    
    Returns:
        list: Sorted list of all unique attributes
    """
    user_attrs = set()
    
    # Load attributes from users
    if os.path.exists(config.USERS_FILE):
        with open(config.USERS_FILE) as f:
            users = json.load(f)
        for user_id, user_data in users.items():
            attrs = get_user_attributes(user_data)
            for attr in attrs:
                # Split comma-separated attributes if present
                if isinstance(attr, str) and "," in attr:
                    for part in attr.split(","):
                        user_attrs.add(part.strip())
                elif attr:
                    user_attrs.add(attr)
    
    # Load attributes from attributes.json
    if os.path.exists(config.ATTRIBUTES_FILE):
        with open(config.ATTRIBUTES_FILE) as f:
            global_attrs = json.load(f)
            user_attrs.update(global_attrs)
    
    return sorted(list(user_attrs))


def save_all_attributes(attributes):
    """
    Save attributes to attributes.json file.
    
    Args:
        attributes: List of attribute strings to save
    """
    with open(config.ATTRIBUTES_FILE, 'w') as f:
        json.dump(attributes, f, indent=2)


def emit_socketio_event(socketio, event_name, data, room='admin_updates'):
    """
    Safely emit a SocketIO event with timestamp.
    
    Args:
        socketio: SocketIO instance
        event_name: Name of the event to emit
        data: Data dictionary to send
        room: Room to broadcast to (default: 'admin_updates')
    """
    if socketio:
        if 'timestamp' not in data:
            data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        socketio.emit(event_name, data, room=room)


def delete_file_and_policy(filename, user_id, ip_address, socketio=None):
    """
    Delete a file and its associated policy.
    
    Args:
        filename: Name of the file to delete
        user_id: ID of the user performing the deletion
        ip_address: IP address of the requester
        socketio: SocketIO instance for real-time updates (optional)
    
    Returns:
        tuple: (success, error_message) - error_message is None if successful
    """
    # Remove file from uploads
    file_path = os.path.join(config.UPLOAD_FOLDER, filename)
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
        log_audit(
            user_id,
            "delete_file",
            details=f"Deleted file {filename}",
            ip=ip_address,
        )
    except Exception as e:
        return False, f"could not remove file: {e}"

    # Remove policy entry if present
    try:
        with open(config.POLICIES_FILE) as f:
            policies = json.load(f)
    except Exception:
        policies = {}

    if filename in policies:
        policies.pop(filename, None)
        try:
            with open(config.POLICIES_FILE, "w") as f:
                json.dump(policies, f, indent=2)
        except Exception as e:
            return False, f"could not update policies: {e}"

    # Broadcast file deletion to all connected users
    if socketio:
        socketio.emit('file_deleted', {
            'deleter': user_id,
            'filename': filename
        }, room='dashboard_updates')
        
        # Emit to admin dashboard
        emit_socketio_event(
            socketio,
            'file_deleted',
            {
                'filename': filename,
                'deleter': user_id,
            },
        )

    return True, None


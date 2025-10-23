import os, json
from flask import Blueprint, request, session, jsonify
from datetime import datetime

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')  # Go up one level to project root
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
ATTRIBUTES_FILE = os.path.join(DATA_DIR, 'attributes.json')

attribute_bp = Blueprint('attribute_bp', __name__)

def get_all_attributes():
    if not os.path.exists(ATTRIBUTES_FILE):
        return []
    with open(ATTRIBUTES_FILE) as f:
        return json.load(f)

def save_all_attributes(attrs):
    with open(ATTRIBUTES_FILE, 'w') as f:
        json.dump(attrs, f, indent=2)

def get_all_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE) as f:
        return json.load(f)

def has_role(user_id, role):
    """Check if a user has a specific role"""
    try:
        users = get_all_users()
        user_data = users.get(user_id)
        if isinstance(user_data, dict):
            roles = user_data.get("roles", [])
            return role in roles or "admin" in roles
        return False
    except Exception:
        return False

def log_audit(user, action, details=None, ip=None):
    """Log audit events"""
    try:
        AUDIT_LOG_FILE = os.path.join(DATA_DIR, 'audit_logs.jsonl')
        entry = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "user": str(user) if user else "unknown",
            "action": str(action) if action else "unknown",
            "details": str(details) if details else "",
            "ip": str(ip) if ip else "",
        }
        with open(AUDIT_LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"Audit logging failed: {e}")

@attribute_bp.route('/admin/add_attribute', methods=['POST'])
def add_attribute():
    user_id = session.get('user_id')
    # Allow admin or role_manager to add attributes
    if user_id != 'admin' and not has_role(user_id, 'role_manager'):
        return jsonify(success=False, error='unauthorized'), 403
    
    data = request.get_json() or {}
    attr = data.get('attr')
    if not attr:
        return jsonify(success=False, error='Attribute required'), 400
    
    # Validate attribute format
    import re
    if not re.match(r'^[A-Za-z0-9_-]+$', attr):
        return jsonify(success=False, error='Invalid attribute format'), 400
    
    attrs = get_all_attributes()
    if attr in attrs:
        return jsonify(success=False, error='Attribute already exists'), 400
    attrs.append(attr)
    save_all_attributes(attrs)
    
    # Log the action
    log_audit(user_id, 'add_attribute', details=f'Added attribute: {attr}', ip=request.remote_addr)
    
    # Import socketio from current module
    from flask import current_app
    socketio = current_app.extensions.get('socketio')
    if socketio:
        socketio.emit('attribute_added', {
            'attribute': attr,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }, room='admin_updates')
    
    return jsonify(success=True)

@attribute_bp.route('/admin/remove_attribute', methods=['POST'])
def remove_attribute():
    user_id = session.get('user_id')
    # Allow admin or role_manager to remove attributes
    if user_id != 'admin' and not has_role(user_id, 'role_manager'):
        return jsonify(success=False, error='unauthorized'), 403
    
    data = request.get_json() or {}
    attr = data.get('attr')
    if not attr:
        return jsonify(success=False, error='Attribute required'), 400
    attrs = get_all_attributes()
    if attr not in attrs:
        return jsonify(success=False, error='Attribute not found'), 404
    users = get_all_users()
    # Check if any user has this attribute
    for u, v in users.items():
        # Normalize user_attrs to a list robustly
        if isinstance(v, dict):
            user_attrs = v.get('attributes')
        elif isinstance(v, str):
            user_attrs = [v]
        else:
            user_attrs = v if v is not None else []
        if user_attrs is None:
            user_attrs = []
        elif isinstance(user_attrs, str):
            user_attrs = [user_attrs]
        elif not isinstance(user_attrs, list):
            user_attrs = list(user_attrs)
        if attr in user_attrs:
            return jsonify(success=False, error='Attribute is associated with a user'), 400
    try:
        attrs.remove(attr)
        save_all_attributes(attrs)
        
        # Log the action
        log_audit(user_id, 'remove_attribute', details=f'Removed attribute: {attr}', ip=request.remote_addr)
        
        # Import socketio from current module
        from flask import current_app
        socketio = current_app.extensions.get('socketio')
        if socketio:
            socketio.emit('attribute_removed', {
                'attribute': attr,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }, room='admin_updates')
        
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=f'Exception: {e}')

def validate_user_attributes(attributes):
    attrs = get_all_attributes()
    for a in attributes:
        if a not in attrs:
            return False, a
    return True, None

@attribute_bp.route('/role_manager/assign_attributes', methods=['POST'])
def role_manager_assign_attributes():
    """Allow role managers to assign attributes to users"""
    user_id = session.get('user_id')
    if user_id != 'admin' and not has_role(user_id, 'role_manager'):
        return jsonify(success=False, error='unauthorized'), 403
    
    data = request.get_json() or {}
    target_user = data.get('user')
    raw_attrs = data.get('attributes', '')
    
    if not target_user:
        return jsonify(success=False, error='User required'), 400
    
    # Parse and validate attributes
    import re
    if isinstance(raw_attrs, list):
        attrs = [str(a).strip() for a in raw_attrs if str(a).strip()]
    elif isinstance(raw_attrs, str):
        attrs = [a.strip() for a in raw_attrs.split(',') if a.strip()]
    else:
        return jsonify(success=False, error='Invalid attributes format'), 400
    
    # Validate attribute format
    pat = re.compile(r'^[A-Za-z0-9_-]+$')
    for attr in attrs:
        if not pat.match(attr):
            return jsonify(success=False, error=f'Invalid attribute: "{attr}"'), 400
    
    # Load users
    users = get_all_users()
    if target_user not in users:
        return jsonify(success=False, error='User not found'), 404
    
    # Ensure user data is in dictionary format
    if not isinstance(users[target_user], dict):
        users[target_user] = {
            'attributes': users[target_user] if isinstance(users[target_user], list) else [],
            'password': users[target_user].get('password') if isinstance(users[target_user], dict) else 'pass',
            'roles': []
        }
    
    old_attrs = users[target_user].get('attributes', [])
    users[target_user]['attributes'] = attrs
    
    # Save users
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
        
        # Log the action
        log_audit(
            user_id,
            'assign_attributes',
            details=f'Assigned attributes to {target_user}: {attrs} (was: {old_attrs})',
            ip=request.remote_addr
        )
        
        # Emit real-time update
        from flask import current_app
        socketio = current_app.extensions.get('socketio')
        if socketio:
            socketio.emit('user_attributes_updated', {
                'user': target_user,
                'attributes': attrs,
                'old_attributes': old_attrs,
                'updated_by': user_id,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }, room='admin_updates')
        
        return jsonify(success=True, attributes=attrs)
    except Exception as e:
        return jsonify(success=False, error=f'Could not save user: {e}'), 500


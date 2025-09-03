import os, json
from flask import Blueprint, request, session, jsonify

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

@attribute_bp.route('/admin/add_attribute', methods=['POST'])
def add_attribute():
    if session.get('user_id') != 'admin':
        return jsonify(success=False, error='unauthorized'), 403
    data = request.get_json() or {}
    attr = data.get('attr')
    if not attr:
        return jsonify(success=False, error='Attribute required'), 400
    attrs = get_all_attributes()
    if attr in attrs:
        return jsonify(success=False, error='Attribute already exists'), 400
    attrs.append(attr)
    save_all_attributes(attrs)
    return jsonify(success=True)

@attribute_bp.route('/admin/remove_attribute', methods=['POST'])
def remove_attribute():
    if session.get('user_id') != 'admin':
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
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=f'Exception: {e}')

def validate_user_attributes(attributes):
    attrs = get_all_attributes()
    for a in attributes:
        if a not in attrs:
            return False, a
    return True, None

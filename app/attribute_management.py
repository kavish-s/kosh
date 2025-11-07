"""
Attribute Management Module
Handles attribute CRUD operations and role-based attribute assignment.
"""
import os
import json
from flask import Blueprint, request, session, jsonify
from datetime import datetime
from . import config
from . import utils

attribute_bp = Blueprint('attribute_bp', __name__)


@attribute_bp.route('/admin/add_attribute', methods=['POST'])
def add_attribute():
    """
    Add a new global attribute (admin or role_manager only).
    
    POST data (JSON):
        attr: Attribute name (alphanumeric, underscore, dash only)
    
    Returns:
        JSON response with success status
    """
    user_id = session.get('user_id')
    # Allow admin or role_manager to add attributes
    if user_id != 'admin' and not utils.has_role(user_id, 'role_manager'):
        return jsonify(success=False, error='unauthorized'), 403
    
    data = request.get_json() or {}
    attr = data.get('attr')
    if not attr:
        return jsonify(success=False, error='Attribute required'), 400
    
    # Validate attribute format
    import re
    if not re.match(r'^[A-Za-z0-9_-]+$', attr):
        return jsonify(success=False, error='Invalid attribute format'), 400
    
    attrs = utils.load_all_attributes()
    if attr in attrs:
        return jsonify(success=False, error='Attribute already exists'), 400
    attrs.append(attr)
    utils.save_all_attributes(attrs)
    
    # Log the action
    utils.log_audit(user_id, 'add_attribute', details=f'Added attribute: {attr}', ip=request.remote_addr)
    
    # Emit real-time update
    from flask import current_app
    socketio = current_app.extensions.get('socketio')
    utils.emit_socketio_event(
        socketio,
        'attribute_added',
        {'attribute': attr},
    )
    
    return jsonify(success=True)


@attribute_bp.route('/admin/remove_attribute', methods=['POST'])
def remove_attribute():
    """
    Remove a global attribute (admin or role_manager only).
    
    POST data (JSON):
        attr: Attribute name to remove
    
    Validation:
        - Cannot remove attribute if it's assigned to any user
    
    Returns:
        JSON response with success status
    """
    user_id = session.get('user_id')
    # Allow admin or role_manager to remove attributes
    if user_id != 'admin' and not utils.has_role(user_id, 'role_manager'):
        return jsonify(success=False, error='unauthorized'), 403
    
    data = request.get_json() or {}
    attr = data.get('attr')
    if not attr:
        return jsonify(success=False, error='Attribute required'), 400
    
    attrs = utils.load_all_attributes()
    if attr not in attrs:
        return jsonify(success=False, error='Attribute not found'), 404
    
    # Check if any user has this attribute
    try:
        with open(config.USERS_FILE) as f:
            users = json.load(f)
    except Exception:
        users = {}
    
    for u, user_data in users.items():
        user_attrs = utils.get_user_attributes(user_data)
        if attr in user_attrs:
            return jsonify(success=False, error='Attribute is associated with a user'), 400
    
    try:
        attrs.remove(attr)
        utils.save_all_attributes(attrs)
        
        # Log the action
        utils.log_audit(user_id, 'remove_attribute', details=f'Removed attribute: {attr}', ip=request.remote_addr)
        
        # Emit real-time update
        from flask import current_app
        socketio = current_app.extensions.get('socketio')
        utils.emit_socketio_event(
            socketio,
            'attribute_removed',
            {'attribute': attr},
        )
        
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=f'Exception: {e}')


@attribute_bp.route('/role_manager/assign_attributes', methods=['POST'])
def role_manager_assign_attributes():
    """
    Allow role managers to assign attributes to users.
    
    POST data (JSON):
        user: Target username
        attributes: Comma-separated attribute list or array
    
    Permissions:
        - Admin or users with role_manager role
    
    Returns:
        JSON response with success status and assigned attributes
    """
    user_id = session.get('user_id')
    if user_id != 'admin' and not utils.has_role(user_id, 'role_manager'):
        return jsonify(success=False, error='unauthorized'), 403
    
    data = request.get_json() or {}
    target_user = data.get('user')
    raw_attrs = data.get('attributes', '')
    
    if not target_user:
        return jsonify(success=False, error='User required'), 400
    
    # Parse and validate attributes
    attrs, err = utils.parse_and_validate_attrs(raw_attrs)
    if err:
        return jsonify(success=False, error=err), 400
    
    # Load users
    try:
        with open(config.USERS_FILE) as f:
            users = json.load(f)
    except Exception:
        return jsonify(success=False, error='could not load users'), 500
    
    if target_user not in users:
        return jsonify(success=False, error='User not found'), 404
    
    # Normalize user data and update attributes
    user_data = utils.normalize_user_data(users[target_user])
    old_attrs = user_data.get('attributes', [])
    user_data['attributes'] = attrs
    users[target_user] = user_data
    
    # Save users
    try:
        with open(config.USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
        
        # Log the action
        utils.log_audit(
            user_id,
            'assign_attributes',
            details=f'Assigned attributes to {target_user}: {attrs} (was: {old_attrs})',
            ip=request.remote_addr
        )
        
        # Emit real-time update
        from flask import current_app
        socketio = current_app.extensions.get('socketio')
        utils.emit_socketio_event(
            socketio,
            'user_attributes_updated',
            {
                'user': target_user,
                'attributes': attrs,
                'old_attributes': old_attrs,
                'updated_by': user_id,
            },
        )
        
        return jsonify(success=True, attributes=attrs)
    except Exception as e:
        return jsonify(success=False, error=f'Could not save user: {e}'), 500


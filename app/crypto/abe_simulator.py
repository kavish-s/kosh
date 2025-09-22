import json

import os, sys
# Define paths to locate the users data file from project root
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Path to crypto directory
APP_DIR = os.path.dirname(BASE_DIR)  # Path to app directory
PROJECT_ROOT = os.path.dirname(APP_DIR)  # Path to project root
USERS_FILE = os.path.join(PROJECT_ROOT, 'data', 'users.json')  # Path to users.json file

def get_user_attributes(user_id):
    """
    Retrieve and normalize the list of attributes for a given user.
    Supports legacy and current user data formats.
    """
    with open(USERS_FILE) as f:
        users = json.load(f)
    # Get user entry; could be a list (legacy) or dict (current)
    user_entry = users.get(user_id, [])
    if isinstance(user_entry, dict):
        attrs = user_entry.get('attributes', [])
    else:
        attrs = user_entry

    # Flatten attributes and handle comma-separated values
    flat_attrs = []
    for attr in attrs:
        if not isinstance(attr, str):
            continue
        flat_attrs.extend([a.strip() for a in attr.split(',') if a.strip()])
    return flat_attrs

def check_access(user_id, policy):
    """
    Check if a user satisfies all attributes required by a policy.
    Policy can be a list of attributes or a comma-separated string.
    Returns True if user has all required attributes, else False.
    """
    user_attrs = get_user_attributes(user_id)

    # Normalize policy to a list of required attributes
    if isinstance(policy, list):
        required = policy
    elif isinstance(policy, str):
        required = [p.strip() for p in policy.split(',')]
    else:
        return False

    # Check if all required attributes are present in user's attributes
    return all(attr in user_attrs for attr in required)
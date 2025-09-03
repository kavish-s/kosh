# crypto/abe_simulator.py

import json

import os, sys
# Always resolve data path from project root
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # crypto directory
APP_DIR = os.path.dirname(BASE_DIR)  # app directory  
PROJECT_ROOT = os.path.dirname(APP_DIR)  # project root
USERS_FILE = os.path.join(PROJECT_ROOT, 'data', 'users.json')

def get_user_attributes(user_id):
    with open(USERS_FILE) as f:
        users = json.load(f)
    # Support multiple user data shapes:
    # 1) { "alice": ["student","year3"] }  (legacy)
    # 2) { "alice": { "attributes": ["student","year3"], "password": "..." } }
    user_entry = users.get(user_id, [])
    # Extract attributes depending on stored shape
    if isinstance(user_entry, dict):
        attrs = user_entry.get('attributes', [])
    else:
        attrs = user_entry

    # Flatten attributes and split any comma-separated values
    flat_attrs = []
    for attr in attrs:
        if not isinstance(attr, str):
            continue
        flat_attrs.extend([a.strip() for a in attr.split(',') if a.strip()])
    return flat_attrs

def check_access(user_id, policy):
    user_attrs = get_user_attributes(user_id)

    if isinstance(policy, list):
        required = policy
    elif isinstance(policy, str):
        required = [p.strip() for p in policy.split(',')]
    else:
        return False

    return all(attr in user_attrs for attr in required)
# crypto/abe_simulator.py

import json

import os, sys
# Always resolve data path from project root
PROJECT_ROOT = sys.path[0]
USERS_FILE = os.path.join(PROJECT_ROOT, 'app', 'data', 'users.json')

def get_user_attributes(user_id):
    with open(USERS_FILE) as f:
        users = json.load(f)
    attrs = users.get(user_id, [])
    # Flatten attributes if any are comma-separated
    flat_attrs = []
    for attr in attrs:
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
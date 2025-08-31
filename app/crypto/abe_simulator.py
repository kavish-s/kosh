# crypto/abe_simulator.py

import json

USERS_FILE = 'data/users.json'

def get_user_attributes(user_id):
    with open(USERS_FILE) as f:
        users = json.load(f)
    return users.get(user_id, [])

def check_access(user_id, policy):
    user_attrs = get_user_attributes(user_id)

    if isinstance(policy, list):
        required = policy
    elif isinstance(policy, str):
        required = [p.strip() for p in policy.split(',')]
    else:
        return False

    return all(attr in user_attrs for attr in required)
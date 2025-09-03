#!/usr/bin/env python3
"""
Test script to verify that new users are created with default password 'pass'
"""

import json
import requests
import os
import sys

# Change to the project directory
os.chdir('/Users/neelshah/Downloads/kosh')

# Read current users
with open('data/users.json', 'r') as f:
    users_before = json.load(f)

print("Users before test:")
for username, user_data in users_before.items():
    if isinstance(user_data, dict):
        password = user_data.get('password', 'NOT SET')
        attributes = user_data.get('attributes', [])
    else:
        password = 'NOT SET (legacy format)'
        attributes = user_data
    print(f"  {username}: password='{password}', attributes={attributes}")

print("\nTesting creation of new user via Flask app...")

# Test creating a new user via Flask app running on localhost
app_url = "http://127.0.0.1:7130"

# First login as admin
session = requests.Session()
login_response = session.post(f"{app_url}/login", data={
    'user_id': 'admin',
    'password': 'pass'
})

if login_response.status_code == 200 and 'admin' in login_response.url:
    print("✓ Successfully logged in as admin")
    
    # Create a new test user
    new_user_response = session.post(f"{app_url}/admin/add_user", json={
        'user': 'testuser123',
        'attributes': 'student,year1,batch3'
    }, headers={
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': 'application/json'
    })
    
    if new_user_response.status_code == 200:
        response_data = new_user_response.json()
        if response_data.get('success'):
            print("✓ Successfully created new user via admin dashboard")
            
            # Read updated users file
            with open('data/users.json', 'r') as f:
                users_after = json.load(f)
            
            if 'testuser123' in users_after:
                new_user_data = users_after['testuser123']
                if isinstance(new_user_data, dict):
                    password = new_user_data.get('password')
                    attributes = new_user_data.get('attributes', [])
                    print(f"✓ New user 'testuser123' created with password='{password}', attributes={attributes}")
                    
                    if password == 'pass':
                        print("✅ SUCCESS: New user has default password 'pass'")
                    else:
                        print(f"❌ FAIL: New user password is '{password}', expected 'pass'")
                else:
                    print(f"❌ FAIL: New user data is not in dictionary format: {new_user_data}")
            else:
                print("❌ FAIL: New user not found in users.json")
        else:
            print(f"❌ FAIL: Server returned success=False: {response_data}")
    else:
        print(f"❌ FAIL: Failed to create user, status={new_user_response.status_code}")
        print(f"Response: {new_user_response.text}")
else:
    print(f"❌ FAIL: Failed to login as admin, status={login_response.status_code}")
    print(f"Response: {login_response.text}")

print("\nFinal users in database:")
with open('data/users.json', 'r') as f:
    final_users = json.load(f)

for username, user_data in final_users.items():
    if isinstance(user_data, dict):
        password = user_data.get('password', 'NOT SET')
        attributes = user_data.get('attributes', [])
    else:
        password = 'NOT SET (legacy format)'
        attributes = user_data
    print(f"  {username}: password='{password}', attributes={attributes}")

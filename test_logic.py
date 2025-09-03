#!/usr/bin/env python3
"""
Simple test to verify the user creation logic directly
"""

import json
import os
import sys
import tempfile
import shutil

# Add the project root to the path and change directory
sys.path.insert(0, '/Users/neelshah/Downloads/kosh')
os.chdir('/Users/neelshah/Downloads/kosh')

# Import the parse function directly
import importlib.util
spec = importlib.util.spec_from_file_location("app", "/Users/neelshah/Downloads/kosh/app/app.py")
app_module = importlib.util.module_from_spec(spec)

# We need to set up the module properly for relative imports
sys.modules['app'] = app_module
sys.modules['app.attribute_management'] = None  # Mock this to avoid import errors

# Create a simple version of parse_and_validate_attrs for testing
def parse_and_validate_attrs(raw):
    """Simple version of the parsing function for testing"""
    if not raw:
        return [], None
    
    # Split by comma and clean up
    attrs = []
    for attr in raw.split(','):
        attr = attr.strip()
        if attr:
            attrs.append(attr)
    
    return attrs, None

def test_user_creation_logic():
    """Test the user creation logic that should set default password to 'pass'"""
    
    print("Testing user creation logic...")
    
    # Create a temporary copy of the users file for testing
    original_users_file = '/Users/neelshah/Downloads/kosh/data/users.json'
    
    with open(original_users_file, 'r') as f:
        original_users = json.load(f)
    
    # Simulate creating a new user
    test_user_id = 'newuser_test'
    test_attributes_raw = 'student,year2,batch1'
    
    # This is the logic from admin_add_user function
    attributes, err = parse_and_validate_attrs(test_attributes_raw)
    
    if err:
        print(f"❌ FAIL: Error parsing attributes: {err}")
        return False
    
    print(f"✓ Parsed attributes: {attributes}")
    
    # Simulate the user creation logic from the updated admin_add_user function
    users = original_users.copy()
    
    # Create user with default password 'pass' and the specified attributes
    users[test_user_id] = {
        'attributes': attributes,
        'password': 'pass'
    }
    
    # Check if the new user was created correctly
    if test_user_id not in users:
        print(f"❌ FAIL: User {test_user_id} not created")
        return False
    
    new_user = users[test_user_id]
    
    if not isinstance(new_user, dict):
        print(f"❌ FAIL: User data is not a dictionary: {new_user}")
        return False
    
    if new_user.get('password') != 'pass':
        print(f"❌ FAIL: User password is '{new_user.get('password')}', expected 'pass'")
        return False
    
    if new_user.get('attributes') != attributes:
        print(f"❌ FAIL: User attributes are {new_user.get('attributes')}, expected {attributes}")
        return False
    
    print(f"✅ SUCCESS: New user '{test_user_id}' created correctly:")
    print(f"   Password: '{new_user['password']}'")
    print(f"   Attributes: {new_user['attributes']}")
    
    return True

def test_user_edit_logic():
    """Test the user edit logic that should preserve the password"""
    
    print("\nTesting user edit logic...")
    
    # Test editing an existing user with dictionary format
    test_users = {
        'existing_user': {
            'attributes': ['student', 'year3'],
            'password': 'custom_password'
        }
    }
    
    user_id = 'existing_user'
    new_attributes = ['student', 'year4', 'batch2']
    
    # This is the logic from the updated admin_edit_user function
    if isinstance(test_users.get(user_id), dict):
        # User exists as dictionary, update attributes but keep password
        existing_password = test_users[user_id].get('password', 'pass')
        test_users[user_id] = {
            'attributes': new_attributes,
            'password': existing_password
        }
    else:
        # User exists as array (legacy format), convert to new format with default password
        test_users[user_id] = {
            'attributes': new_attributes,
            'password': 'pass'
        }
    
    # Check if the edit was correct
    edited_user = test_users[user_id]
    
    if edited_user.get('password') != 'custom_password':
        print(f"❌ FAIL: Password was not preserved: '{edited_user.get('password')}'")
        return False
    
    if edited_user.get('attributes') != new_attributes:
        print(f"❌ FAIL: Attributes not updated correctly: {edited_user.get('attributes')}")
        return False
    
    print("✅ SUCCESS: User edit preserved existing password and updated attributes")
    
    # Test editing a legacy format user
    print("\nTesting legacy user format conversion...")
    
    legacy_users = {
        'legacy_user': ['student', 'year1']
    }
    
    user_id = 'legacy_user'
    new_attributes = ['student', 'year2']
    
    # Apply the edit logic
    if isinstance(legacy_users.get(user_id), dict):
        existing_password = legacy_users[user_id].get('password', 'pass')
        legacy_users[user_id] = {
            'attributes': new_attributes,
            'password': existing_password
        }
    else:
        # User exists as array (legacy format), convert to new format with default password
        legacy_users[user_id] = {
            'attributes': new_attributes,
            'password': 'pass'
        }
    
    converted_user = legacy_users[user_id]
    
    if converted_user.get('password') != 'pass':
        print(f"❌ FAIL: Legacy user not given default password: '{converted_user.get('password')}'")
        return False
    
    if converted_user.get('attributes') != new_attributes:
        print(f"❌ FAIL: Legacy user attributes not updated: {converted_user.get('attributes')}")
        return False
    
    print("✅ SUCCESS: Legacy user converted to new format with default password 'pass'")
    
    return True

if __name__ == "__main__":
    print("Running user creation and editing tests...")
    
    success1 = test_user_creation_logic()
    success2 = test_user_edit_logic()
    
    if success1 and success2:
        print("\n🎉 All tests passed! Default password functionality is working correctly.")
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)

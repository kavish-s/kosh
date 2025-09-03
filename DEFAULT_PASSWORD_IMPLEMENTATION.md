# Default Password Implementation

## Summary of Changes

This document describes the changes made to ensure that all users (existing and new) have a default password of 'pass'.

## Changes Made

### 1. Updated User Data Format
- All users in `data/users.json` now use the consistent dictionary format:
  ```json
  {
    "username": {
      "attributes": ["attr1", "attr2"],
      "password": "pass"
    }
  }
  ```

### 2. Modified `admin_add_user` Function (app/app.py)
- Updated the user creation logic to include default password:
  ```python
  # OLD CODE:
  users[user_id] = attributes
  
  # NEW CODE:
  users[user_id] = {
      'attributes': attributes,
      'password': 'pass'
  }
  ```

### 3. Enhanced `admin_edit_user` Function (app/app.py)
- Preserves existing passwords when editing user attributes
- Converts legacy array format to new dictionary format with default password
- Logic:
  - If user exists as dictionary: preserve existing password
  - If user exists as array (legacy): convert to dictionary with default password 'pass'

### 4. Updated Users File (data/users.json)
- Converted legacy users "das" and "kale" from array format to dictionary format
- All users now have consistent structure with default password 'pass'

## Verification

The implementation has been tested to ensure:
1. ✅ All existing users have password 'pass'
2. ✅ New users created through admin dashboard get default password 'pass'
3. ✅ Editing user attributes preserves existing passwords
4. ✅ Legacy format users are converted to new format with default password
5. ✅ Application continues to work correctly

## Backward Compatibility

The application maintains backward compatibility:
- The login function and other parts of the codebase already handle both user data formats
- Existing code that reads user attributes works with the new format
- The crypto/abe_simulator.py properly extracts attributes from both formats

## Security Note

The default password 'pass' is used for simplicity. In a production environment, consider:
- Generating random passwords for new users
- Requiring users to change their password on first login
- Implementing password strength requirements

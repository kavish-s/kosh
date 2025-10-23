"""
Crypto package initialization.
Provides encryption and ABE functionality for the Kosh application.
"""

from .aes import encrypt, decrypt
from .abe_simulator import check_access, get_user_attributes

__all__ = ['encrypt', 'decrypt', 'check_access', 'get_user_attributes']

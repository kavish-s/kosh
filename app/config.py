"""
Configuration file for Kosh application.
Centralizes all application settings and paths.
"""
import os

# Base directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

# Data files
USERS_FILE = os.path.join(DATA_DIR, "users.json")
POLICIES_FILE = os.path.join(DATA_DIR, "policies.json")
ATTRIBUTES_FILE = os.path.join(DATA_DIR, "attributes.json")
AUDIT_LOG_FILE = os.path.join(DATA_DIR, "audit_logs.jsonl")
AES_KEY_PATH = os.path.join(DATA_DIR, "aes_encryption.key")
HMAC_KEY_PATH = os.path.join(DATA_DIR, "aes_hmac.key")

# Application settings
SECRET_KEY = os.environ.get("KOSH_SECRET_KEY", "kosh-secret-key-change-in-production")
DEBUG = os.environ.get("KOSH_DEBUG", "True").lower() == "true"
HOST = os.environ.get("KOSH_HOST", "10.125.161.57")
PORT = int(os.environ.get("KOSH_PORT", "7130"))

# Security settings
AUDIT_LOG_RETENTION_DAYS = int(os.environ.get("KOSH_AUDIT_RETENTION_DAYS", "60"))
DEFAULT_PASSWORD = "pass"  # Default password for new users

# File upload settings
MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024  # 5GB
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'csv',
    'jpg', 'jpeg', 'png', 'gif', 'zip', 'rar', 'py', 'js', 'json',
    'mp4', 'mov', 'avi', 'mkv'
}

# Encryption settings
IV_SIZE = 16  # AES block size
CHUNK_SIZE = 65536  # 64KB
TAG_SIZE = 32  # HMAC-SHA256 output size


def ensure_directories():
    """Create necessary directories if they don't exist."""
    for directory in [UPLOAD_FOLDER, DATA_DIR]:
        os.makedirs(directory, exist_ok=True)

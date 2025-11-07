# Kosh - LAN-Based Secure File Sharing with Simulated ABE

**Kosh** is a modern Flask application for secure file sharing over a local network using AES encryption and simulated Attribute-Based Encryption (ABE). It features a beautiful Tailwind-based UI, an admin dashboard for user and policy management, real-time synchronization, and improved file structure for scalability.

## 🌟 Table of Contents

- [Quick Setup](#-quick-setup)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Real-Time Features](#-real-time-features)
- [Security](#-security)
- [Architecture](#-architecture)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Quick Setup

### Simple Setup for Capstone Project

#### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

#### 2. Run the Application

```bash
python3 -m app.app
```

#### 3. Access the Application

Open your browser: `http://localhost:7130`

**Default Login:**
- Username: `admin`
- Password: `pass`

#### 4. That's It!

The application is now running. You can:
- Upload encrypted files
- Set access policies based on user attributes
- Manage users and their attributes
- View audit logs

**Note:** All files stored in `data/` and `app/uploads/`. Simple JSON-based storage (no database needed). Real-time updates using WebSockets. AES encryption for all files.

## 📦 Dependencies

Kosh uses minimal, well-maintained dependencies:

- **Flask 3.1.2** - Web framework
- **flask-socketio 5.5.1** - WebSocket support for real-time features
- **flask-cors 6.0.1** - CORS handling
- **cryptography 45.0.7** - Encryption library (AES, HMAC)
- **werkzeug 3.1.3** - WSGI utilities and password hashing

All dependencies are specified in `requirements.txt` and can be installed with:

```bash
pip install -r requirements.txt
```

## ⚙️ Configuration

Kosh uses a centralized configuration system (`app/config.py`) with environment variable support.

### Environment Variables

Create a `.env` file from the template:

```bash
cp .env.example .env
```

Available configuration options:

| Variable | Default | Description |
|----------|---------|-------------|
| `KOSH_SECRET_KEY` | `kosh-secret-key-change-in-production` | Flask secret key for sessions |
| `KOSH_DEBUG` | `True` | Enable debug mode |
| `KOSH_HOST` | `0.0.0.0` | Host to bind to (0.0.0.0 = all interfaces) |
| `KOSH_PORT` | `7130` | Port to run on |
| `KOSH_AUDIT_RETENTION_DAYS` | `60` | Days to keep audit logs |

### File Upload Configuration

Configured in `app/config.py`:

```python
MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024  # 5GB
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'csv',
    'jpg', 'jpeg', 'png', 'gif', 'zip', 'rar', 'py', 'js', 'json',
    'mp4', 'mov', 'avi', 'mkv'
}
```

### Encryption Configuration

```python
IV_SIZE = 16        # AES block size (bytes)
CHUNK_SIZE = 65536  # 64KB chunks for stream processing
TAG_SIZE = 32       # HMAC-SHA256 output size (bytes)
```

### Directory Structure

Automatically created on first run:

- `data/` - Data files (users, policies, attributes, audit logs, keys)
- `app/uploads/` - Encrypted file storage



## 🌐 Features

### Core Features
- 🔒 **AES-256-CTR encryption** with HMAC-SHA256 for authenticated file encryption
- 🧑‍💻 **User-based attribute system** for granular access control
- 🔐 **Simulated ABE access control** using JSON-based policies
- 🎛️ **Comprehensive admin dashboard** for managing users, attributes, and file policies
- � **Role-based access control** with role_manager permissions for delegated administration
- �💡 **Modern Tailwind CSS UI** for all pages with responsive design
- 📁 **No cloud dependency** – works entirely on LAN
- 📊 **File policies with metadata** (policy, key, uploader, timestamp)
- 🗑️ **Automatic audit log cleanup** with configurable retention period
- 📥 **Audit log export** functionality for compliance and analysis

### Real-Time Features (WebSocket)
- 🔄 **Live synchronization** across all admin sessions using Flask-SocketIO
- 📱 **Toast notifications** for user feedback and operation status
- 🌐 **Auto-reconnection** and connection status indicators
- 📝 **Live audit logs** streamed to admin dashboard
- ⚡ **Bulk operations** with real-time updates (users, policies, attributes)
- 🔔 **Instant notifications** for user additions, deletions, policy changes
- 📊 **Real-time dashboard updates** when files are uploaded or deleted

### Security Features
- 🔐 **AES-256-CTR encryption** for all file operations
- 🔑 **HMAC-SHA256** for data integrity verification
- 🛡️ **Attribute-based access control** with flexible policy definitions
- 👥 **Session-based authentication** with secure password hashing (Werkzeug)
- 🔍 **Comprehensive audit logging** for all administrative and user actions
- 🚫 **Input validation** and sanitization to prevent injection attacks
- 🔒 **Secure key storage** with auto-generated encryption keys
- ⏰ **Configurable audit log retention** for compliance requirements

## 📁 Project Structure

```
kosh/
├── app/
│   ├── __init__.py                 # Package initialization
│   ├── app.py                      # Main Flask application with routes and WebSocket handlers
│   ├── attribute_management.py     # Attribute CRUD operations and role-based management
│   ├── config.py                   # Centralized configuration and environment settings
│   ├── utils.py                    # Shared utility functions for the application
│   ├── crypto/
│   │   ├── __init__.py
│   │   ├── aes.py                  # AES-256 encryption/decryption with HMAC
│   │   └── abe_simulator.py        # JSON-based ABE access control simulation
│   ├── static/
│   │   ├── admin/                  # Admin dashboard specific assets
│   │   │   ├── admin.css
│   │   │   ├── admin-dashboard.js
│   │   │   └── tailwind.config.js
│   │   ├── dashboard/              # User dashboard specific assets
│   │   │   ├── dashboard.css
│   │   │   ├── dashboard.js
│   │   │   └── dashboard-tailwind.config.js
│   │   ├── shared/                 # Shared components and utilities
│   │   │   ├── components/         # Reusable UI components
│   │   │   │   ├── modal.js
│   │   │   │   ├── notification-manager.js
│   │   │   │   └── toast.js
│   │   │   ├── modules/            # Feature-specific modules
│   │   │   │   ├── attribute-manager.js
│   │   │   │   ├── audit-manager.js
│   │   │   │   ├── dashboard-file-manager.js
│   │   │   │   ├── file-manager.js
│   │   │   │   ├── password-manager.js
│   │   │   │   ├── policy-manager.js
│   │   │   │   ├── realtime-manager.js
│   │   │   │   ├── role-manager.js
│   │   │   │   ├── role-manager-attribute.js
│   │   │   │   ├── upload-manager.js
│   │   │   │   └── user-manager.js
│   │   │   └── utils/              # UI helper utilities
│   │   │       ├── admin-links.js
│   │   │       └── ui-helpers.js
│   │   └── common/                 # Common assets (favicons, icons, PWA manifest)
│   │       ├── android-chrome-192x192.png
│   │       ├── android-chrome-512x512.png
│   │       ├── apple-touch-icon.png
│   │       ├── favicon-16x16.png
│   │       ├── favicon-32x32.png
│   │       ├── favicon.ico
│   │       └── site.webmanifest
│   ├── templates/
│   │   ├── index.html              # Login page
│   │   ├── dashboard.html          # User dashboard
│   │   └── admin.html              # Admin dashboard
│   └── uploads/                    # Encrypted file storage (auto-created)
├── data/
│   ├── aes_encryption.key          # AES encryption key (auto-generated)
│   ├── aes_hmac.key                # HMAC key for integrity (auto-generated)
│   ├── attributes.json             # Global attribute pool
│   ├── audit_logs.jsonl            # System audit logs (JSONL format)
│   ├── policies.json               # File access policies
│   └── users.json                  # User accounts and attributes
├── .github/                        # GitHub templates and workflows
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md
│       └── feature_request.md
├── .env.example                    # Environment configuration template
├── .gitignore                      # Git ignore patterns
├── requirements.txt                # Python dependencies
├── LICENSE                         # License information
└── README.md                       # This file
```

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Modern web browser with WebSocket support

### 1. Clone the Repository

```bash
git clone https://github.com/neelshha/kosh.git
cd kosh
```

### 2. Set Up Virtual Environment

```bash
python -m venv venv
source venv/bin/activate        # On macOS/Linux
# or
venv\Scripts\activate           # On Windows
pip install -r requirements.txt
```

### 3. Configure Environment (Optional)

The application works with default settings, but you can customize it:

```bash
cp .env.example .env
# Edit .env file to customize settings
```

Available environment variables:

- `KOSH_SECRET_KEY`: Flask secret key (change in production)
- `KOSH_DEBUG`: Enable debug mode (default: True)
- `KOSH_HOST`: Host to bind to (default: 0.0.0.0)
- `KOSH_PORT`: Port to run on (default: 7130)
- `KOSH_AUDIT_RETENTION_DAYS`: Days to keep audit logs (default: 60)

### 4. Run the Application

```bash
python -m app.app
```

The application will:

- Auto-create necessary directories (`data/`, `app/uploads/`)
- Generate encryption keys if they don't exist
- Initialize default data files
- Start audit log cleanup background task
- Launch the server on `http://localhost:7130`

You can access it from any device on the same local network.

### 5. Default Login Credentials

- **Admin User**: `admin` / `pass`
- **Regular Users**: Default password is `pass` for all users

### 6. Admin Dashboard Access

- Navigate to `http://localhost:7130/admin` after logging in as admin
- Manage users, attributes, and file policies
- View real-time audit logs and system activity
- Export audit logs for compliance

## 🔄 Real-Time Features

Kosh includes comprehensive real-time synchronization using WebSocket technology (Socket.IO):

### Live Updates
- **User Management**: Add, edit, delete users with instant UI updates
- **Policy Management**: Create, modify, remove file access policies
- **Attribute Management**: Add/remove attributes from the global pool
- **Bulk Operations**: Mass user/policy operations with live feedback
- **Audit Logs**: Live audit trail of all system activities

### WebSocket Events
- `user_added`, `user_updated`, `user_deleted`
- `policy_added`, `policy_updated`, `policy_deleted`
- `attribute_added`, `attribute_removed`
- `audit_log_added` for system activity tracking

### Testing Real-Time Features
Open multiple browser tabs as admin to see live synchronization:
1. Login as admin in multiple tabs
2. Perform operations in one tab
3. Observe instant updates in all other tabs

### Technical Implementation

#### Backend (Flask-SocketIO)
```python
# Admin room management
@socketio.on('join_admin')
def handle_join_admin():
    user_id = session.get('user_id')
    if user_id == 'admin':
        join_room('admin_updates')
        emit('joined_admin', {'message': 'Joined admin updates'})

# Real-time event emission
socketio.emit('user_added', {
    'user': user_id,
    'attributes': attributes,
    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}, room='admin_updates')
```

#### Frontend (JavaScript + Socket.IO)
```javascript
// Initialize connection
const socket = io();
socket.emit('join_admin');

// Listen for real-time events
socket.on('user_added', function(data) {
    addUserToTable(data.user, data.attributes);
    showToast(`User "${data.user}" added`, 'success');
});
```

### Configuration
For production environments, configure specific CORS origins:
```python
socketio = SocketIO(app, cors_allowed_origins=["https://yourdomain.com"])
```

### Browser Compatibility
Real-time features work in all modern browsers supporting WebSocket:
- Chrome 16+, Firefox 11+, Safari 7+, Edge (all versions)
- Mobile browsers with WebSocket support

## 🔒 Security

### Encryption Implementation

**AES-256-CTR with HMAC-SHA256**

All files are encrypted using industry-standard AES-256 in CTR mode with HMAC authentication:

- **Encryption**: AES-256-CTR mode for file content
- **Integrity**: HMAC-SHA256 for tamper detection
- **Key Management**: Auto-generated 256-bit keys stored securely
- **IV Handling**: Random 16-byte IV for each file
- **Stream Processing**: 64KB chunks for memory efficiency

**Encryption Format:**

```
[16-byte IV][Encrypted File Data][32-byte HMAC Tag]
```

**Key Files:**

- `data/aes_encryption.key` - AES encryption key (auto-generated)
- `data/aes_hmac.key` - HMAC authentication key (auto-generated)

### Access Control

**Attribute-Based Access Control (ABE Simulation)**

- Files protected by attribute-based policies
- Users assigned multiple attributes
- Access granted only if user has ALL required attributes
- Policies stored as JSON for flexibility and transparency

**Role-Based Permissions**

- **Admin**: Full system access, user management, policy management
- **Role Manager**: Can assign attributes to users
- **Regular Users**: File upload/download based on attributes

### Authentication & Session Management

- **Password Hashing**: Werkzeug's secure password hashing (PBKDF2)
- **Session-Based Auth**: Flask sessions with secure secret key
- **Default Password**: `pass` for all users (change in production)
- **Password Change**: Users can change their own passwords

### Input Validation & Security

- File upload validation (size, type, content)
- Attribute format validation (alphanumeric, underscore, dash only)
- Policy validation before file access
- HTML escaping to prevent XSS
- JSON schema validation for API requests

### Audit Trail

- **Comprehensive Logging**: All actions logged with user, timestamp, IP, and details
- **JSONL Format**: Efficient append-only audit log
- **Auto-Cleanup**: Configurable retention period (default: 60 days)
- **Export Capability**: Download audit logs for compliance
- **Real-Time Streaming**: Live audit logs in admin dashboard

### Default Password Implementation

All users have a consistent password structure:

- **Default password**: `pass` for all users
- **Backward compatibility** with legacy user formats
- **Secure password change** functionality available

The system automatically converts legacy user formats to the new dictionary format:

```json
{
  "username": {
    "attributes": ["attr1", "attr2"],
    "password": "hashed_password"
  }
}
```

### Security Best Practices

**For Production Deployment:**

1. **Change Secret Key**: Set `KOSH_SECRET_KEY` environment variable
2. **Change Default Passwords**: Update all user passwords
3. **Disable Debug Mode**: Set `KOSH_DEBUG=False`
4. **Use HTTPS**: Deploy behind reverse proxy with SSL/TLS
5. **Restrict CORS**: Configure specific origins in production
6. **Network Isolation**: Use on trusted local network only
7. **File Permissions**: Ensure proper permissions on `data/` directory
8. **Regular Backups**: Backup `data/` directory regularly
9. **Monitor Audit Logs**: Review logs for suspicious activity
10. **Update Dependencies**: Keep Python packages up to date

### Known Limitations

- **Not for Public Internet**: Designed for LAN use only
- **JSON Storage**: Not suitable for large-scale deployments
- **ABE Simulation**: Uses policy-based access, not cryptographic ABE
- **File Size**: Large files may impact performance (default max: 5GB)

### Reporting Security Vulnerabilities

Please report security vulnerabilities by creating an issue with the "security" label.

**Supported Versions:**

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | ✅ |
| 5.0.x   | ❌ |
| 4.0.x   | ✅ |
| < 4.0   | ❌ |

**Include in your report:**

- Clear description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested mitigation if known

## 🏗️ Architecture

### Modular Design

Kosh follows a modular architecture with clear separation of concerns:

#### Backend Components

**Core Application (`app.py`)**

- Flask routes for authentication, file operations, and admin functions
- WebSocket event handlers for real-time features
- 30+ endpoints for complete application functionality
- Background audit log cleanup thread

**Configuration Module (`config.py`)**

Centralizes all application settings:

- Directory paths (uploads, data, templates, static)
- File paths (users, policies, attributes, audit logs, encryption keys)
- Application settings (secret key, debug mode, host, port)
- Security settings (audit retention, default password)
- File upload settings (max size, allowed extensions)
- Encryption settings (IV size, chunk size, tag size)

**Utility Module (`utils.py`)**

Shared helper functions:

- `safe_load_json()`: Safe JSON file loading with error handling
- `parse_and_validate_attrs()`: Attribute input normalization and validation
- `log_audit()`: Comprehensive audit logging with WebSocket emission
- `has_role()`: Role-based permission checking
- `initialize_data_files()`: Bootstrap default data files
- `validate_file_upload()`: File upload validation
- `get_user_files()`: User-accessible file listing with ABE filtering
- `normalize_user_data()`: Legacy/current user format normalization
- `emit_socketio_event()`: Centralized WebSocket event emission
- `delete_file_and_policy()`: File deletion with policy cleanup

**Attribute Management Module (`attribute_management.py`)**

Dedicated blueprint for attribute operations:

- `/admin/add_attribute`: Add global attributes (admin/role_manager)
- `/admin/remove_attribute`: Remove attributes with validation
- `/role_manager/assign_attributes`: Delegated attribute assignment
- Real-time WebSocket events for all operations
- Comprehensive audit logging

**Crypto Module**

- `aes.py`: AES-256-CTR encryption with HMAC-SHA256 authentication
  - `encrypt()`: Stream-based file encryption
  - `decrypt()`: Stream-based file decryption with integrity verification
  - Auto-generates encryption keys on first run
  
- `abe_simulator.py`: Policy-based access control
  - `get_user_attributes()`: Retrieves user attributes from users.json
  - `check_access()`: Validates if user satisfies policy requirements
  - Supports legacy and current user data formats

#### Frontend Architecture

**Modular JavaScript Structure**

The frontend follows a component-based architecture with three layers:

**1. Components (`static/shared/components/`)**

Reusable UI components:

- `modal.js`: Generic modal dialog system
- `toast.js`: Toast notification component
- `notification-manager.js`: Centralized notification system

**2. Modules (`static/shared/modules/`)**

Feature-specific functionality:

- `realtime-manager.js`: WebSocket connection and event handling
- `user-manager.js`: User CRUD operations
- `attribute-manager.js`: Global attribute management
- `policy-manager.js`: File access policy management
- `file-manager.js`: Admin file management
- `dashboard-file-manager.js`: User file listing and operations
- `upload-manager.js`: File upload with policy definition
- `password-manager.js`: Password change functionality
- `audit-manager.js`: Audit log viewing and filtering
- `role-manager.js`: Role assignment interface
- `role-manager-attribute.js`: Delegated attribute assignment

**3. Utilities (`static/shared/utils/`)**

Helper functions:

- `ui-helpers.js`: Common UI manipulation functions
- `admin-links.js`: Admin navigation helpers

**Dashboard-Specific Assets**

- `admin/`: Admin dashboard CSS, JS, and Tailwind config
- `dashboard/`: User dashboard CSS, JS, and Tailwind config
- `common/`: Favicons, PWA manifest, icons

#### Data Layer

**JSON-Based Storage**

Simple, file-based data persistence:

**users.json** - User accounts with attributes and passwords
```json
{
  "username": {
    "attributes": ["attr1", "attr2"],
    "password": "hashed_password"
  }
}
```

**attributes.json** - Global attribute pool
```json
["finance", "engineering", "hr", "executive"]
```

**policies.json** - File access policies
```json
{
  "encrypted_filename.enc": {
    "policy": ["finance", "executive"],
    "key": "encrypted_file_key",
    "uploader": "admin",
    "timestamp": "2025-11-07 10:30:45"
  }
}
```

**audit_logs.jsonl** - Activity logs (JSON Lines format)
```json
{"user": "admin", "action": "add_user", "details": "Added user: john", "time": "2025-11-07 10:30:45", "ip": "127.0.0.1"}
```

### Request Flow

**File Upload Flow:**

1. User selects file and defines access policy
2. Frontend validates file and sends to `/upload` endpoint
3. Backend encrypts file with AES-256-CTR
4. Generates encrypted file key with policy
5. Stores encrypted file in `app/uploads/`
6. Saves policy metadata to `policies.json`
7. Logs action to audit log
8. Emits WebSocket event to update all connected clients

**File Download Flow:**

1. User requests file via `/download/<filename>`
2. Backend loads policy from `policies.json`
3. ABE simulator checks if user has required attributes
4. If authorized, decrypts file in memory
5. Streams decrypted file to user
6. Logs download action to audit log

**Real-Time Update Flow:**

1. Admin performs action (add user, update policy, etc.)
2. Backend processes request and updates data files
3. Logs action to `audit_logs.jsonl`
4. Emits WebSocket event with update data
5. All connected admin clients receive event
6. Frontend modules update UI reactively
7. Toast notification confirms action

### Key Features Implementation

**Attribute-Based Access Control:**

- Users assigned attributes (e.g., "finance", "engineering")
- Files protected by policies requiring specific attributes
- Access granted only if user has ALL required attributes
- Supports comma-separated attribute lists
- ABE simulation provides granular access control without cryptographic ABE

**Role-Based Administration:**

- Admin: Full system access
- Role Manager: Can manage user attributes
- Regular Users: Upload/download files based on attributes
- Role delegation enables distributed administration

**Audit Trail:**

- All actions logged with user, timestamp, IP, and details
- JSONL format for efficient append and stream processing
- Auto-cleanup after configurable retention period (default: 60 days)
- Export functionality for compliance reporting
- Real-time log streaming to admin dashboard

### Dashboard Architecture

The application features a well-structured dashboard system with separated concerns:

#### Admin Dashboard

Located at `/admin`, provides comprehensive administrative functionality:

**Features:**

- User management (add, edit, delete, bulk operations)
- Attribute management (global attribute pool)
- Policy management (file access control)
- Role assignment (role_manager permissions)
- File management (view all files, delete)
- Audit log viewing and export
- Real-time updates via WebSocket

**Structure:**

```
app/static/admin/
├── admin.css                    # Admin-specific styles
├── admin-dashboard.js           # Main admin controller
└── tailwind.config.js           # Tailwind configuration
```

#### User Dashboard

Located at `/dashboard`, provides user-facing functionality:

**Features:**

- View accessible files based on attributes
- Upload files with policy definition
- Download authorized files
- Delete own uploaded files
- Change password
- Real-time file list updates

**Structure:**

```
app/static/dashboard/
├── dashboard.css                # User dashboard styles
├── dashboard.js                 # Main dashboard controller
└── dashboard-tailwind.config.js # Tailwind configuration
```

#### Shared Components

Reusable components and modules used across both dashboards:

```
app/static/shared/
├── components/              # UI components
│   ├── modal.js            # Generic modal system
│   ├── toast.js            # Toast notifications
│   └── notification-manager.js
├── modules/                 # Feature modules
│   ├── realtime-manager.js # WebSocket handling
│   ├── user-manager.js     # User CRUD
│   ├── attribute-manager.js
│   ├── policy-manager.js
│   ├── file-manager.js
│   ├── upload-manager.js
│   ├── password-manager.js
│   ├── audit-manager.js
│   ├── role-manager.js
│   ├── role-manager-attribute.js
│   └── dashboard-file-manager.js
└── utils/                   # Helper utilities
    ├── ui-helpers.js
    └── admin-links.js
```

#### Key Benefits

- ✅ **Separation of Concerns**: CSS, JavaScript, and HTML in separate files
- ✅ **Reusability**: Shared components across admin and user dashboards
- ✅ **Maintainability**: Easy to locate and modify specific functionality
- ✅ **Performance**: Better caching and reduced inline scripts
- ✅ **Scalability**: Easy to add new features and components
- ✅ **Developer Experience**: Better code readability and debugging

## 💻 Development

### API Endpoints

#### Authentication Routes

- `GET /` - Login page
- `POST /login` - User authentication
- `GET /logout` - End user session

#### User Dashboard Routes

- `GET /dashboard` - Main user dashboard (shows accessible files)
- `GET /api/files` - Get list of files user can access (JSON)
- `POST /change_password` - Change user password
- `POST /upload` - Upload and encrypt file with policy
- `GET /download/<filename>` - Download and decrypt file
- `POST /delete_file` - Delete user's uploaded file

#### Admin Routes

- `GET /admin` - Admin dashboard
- `POST /admin/add_user` - Create new user
- `POST /admin/edit_user/<user_id>` - Update user information
- `GET /admin/delete_user/<user_id>` - Delete single user (legacy)
- `POST /admin/delete_user` - Delete user with audit log
- `POST /admin/bulk_delete_users` - Delete multiple users
- `POST /admin/update_user_roles` - Assign roles to users
- `POST /admin/bulk_set_attrs` - Bulk assign attributes to users

#### Policy Management Routes

- `POST /admin/add_policy` - Create file access policy
- `POST /admin/edit_policy/<file>` - Update file policy
- `GET /admin/delete_policy/<file>` - Delete single policy (legacy)
- `POST /admin/delete_policy` - Delete policy with audit log
- `POST /admin/bulk_delete_policies` - Delete multiple policies
- `POST /admin/delete_file` - Admin delete file with policy

#### Attribute Management Routes (Blueprint)

- `POST /admin/add_attribute` - Add global attribute
- `POST /admin/remove_attribute` - Remove global attribute
- `POST /role_manager/assign_attributes` - Role manager attribute assignment

#### Audit Routes

- `GET /admin/download_audit_logs` - Export audit logs (JSON)

#### WebSocket Events

**Connection Events:**

- `connect` - Client connection established
- `disconnect` - Client disconnected
- `join_admin` - Join admin updates room
- `leave_admin` - Leave admin updates room
- `join_dashboard` - Join dashboard updates room
- `leave_dashboard` - Leave dashboard updates room

**Server-Emitted Events:**

- `user_added` - New user created
- `user_updated` - User information changed
- `user_deleted` - User removed
- `users_bulk_deleted` - Multiple users deleted
- `user_attributes_updated` - User attributes changed
- `policy_added` - New file policy created
- `policy_updated` - Policy modified
- `policy_deleted` - Policy removed
- `policies_bulk_deleted` - Multiple policies deleted
- `attribute_added` - Global attribute added
- `attribute_removed` - Global attribute removed
- `audit_log_added` - New audit log entry
- `file_deleted` - File removed

### Code Style Guidelines

- **Python**: Follow PEP8 standards
- **JavaScript**: Use ES6+ features, modular architecture
- **CSS**: Use Tailwind classes, organized structure
- **HTML**: Semantic HTML5 elements with proper ARIA attributes

### Adding New Features

#### Backend Real-Time Events

```python
# Emit events after data changes
from flask import current_app
socketio = current_app.extensions.get('socketio')
utils.emit_socketio_event(socketio, 'custom_event', data, room='admin_updates')
```

#### Frontend Event Handling

```javascript
// Listen for events and update UI
socket.on('custom_event', function(data) {
    updateUIElement(data);
    showToast('Action completed', 'success');
});
```

### Event Naming Convention

- Use descriptive names: `user_added` not `ua`
- Include entity type: `policy_updated` not `updated`
- Use past tense: `file_deleted` not `file_delete`

### UI Update Best Practices

- Always escape HTML to prevent XSS
- Use smooth animations for better UX
- Show loading states during operations
- Provide user feedback via toast notifications

### Performance Considerations

- **Event Batching**: Efficient handling of rapid changes
- **Memory Management**: Limited audit log retention in UI
- **Connection Pooling**: Optimized WebSocket connections
- **Selective Updates**: Only affected UI elements are updated
- **Stream Processing**: Large files encrypted/decrypted in chunks (64KB)

### Testing Guidelines

**Testing Real-Time Features:**

Open multiple browser tabs as admin to see live synchronization:

1. Login as admin in multiple tabs
2. Perform operations in one tab
3. Observe instant updates in all other tabs

**Testing File Access Control:**

1. Create users with different attributes
2. Upload files with varying policy requirements
3. Login as different users to verify access control
4. Check audit logs for all operations

## 🤝 Contributing

We welcome contributions from the community! Whether it's fixing a bug, improving documentation, or adding a new feature, all contributions are welcome.

### Getting Started
1. **Fork the Repository**: Click the Fork button in the top-right corner
2. **Clone your fork locally**:
   ```bash
   git clone https://github.com/<your-username>/kosh.git
   cd kosh
   ```
3. **Set upstream remote** (recommended):
   ```bash
   git remote add upstream https://github.com/neelshha/kosh.git
   ```
4. **Create a feature branch**:
   ```bash
   git checkout -b feature/<short-description>
   ```

### Contribution Guidelines

#### Commit Message Format
Follow [Conventional Commits](https://www.conventionalcommits.org/):
```
<type>: <short description>

feat: add real-time file upload progress
fix: resolve WebSocket connection issues
docs: update installation instructions
refactor: restructure dashboard components
style: formatting changes, no code logic updates
test: adding or updating tests
```

#### Code Requirements
- Follow existing code style and patterns
- Use **Bootstrap/Tailwind** classes instead of inline CSS
- Keep code modular and reusable
- Avoid committing secrets, API keys, or passwords
- Include comments for complex logic
- Test your changes across different browsers

### Types of Contributions
- 🐛 **Bug fixes**: Help us squash bugs
- ✨ **New features**: Add exciting new functionality
- 📚 **Documentation**: Improve our docs
- 🎨 **UI/UX**: Enhance the user interface
- ⚡ **Performance**: Optimize existing code
- 🧪 **Testing**: Add or improve tests

### Issue Templates
Use our GitHub issue templates for:

#### Bug Reports
- Clear description of the bug
- Steps to reproduce the behavior
- Expected vs actual behavior
- Screenshots if applicable
- Environment details (OS, browser, version)

#### Feature Requests
- Problem description or motivation
- Proposed solution
- Alternative solutions considered
- Additional context or mockups

### Pull Request Process
1. **Ensure code quality**: Make sure your code is tested and follows our guidelines
2. **Update documentation**: Include relevant documentation updates
3. **Test thoroughly**: Verify your changes work across different scenarios
4. **Push your branch**: 
   ```bash
   git push origin feature/<branch-name>
   ```
5. **Open a Pull Request**: Provide a clear title and description, link related issues

### Development Setup
1. Set up virtual environment as described in Getting Started
2. Install development dependencies if any
3. Run the application locally to test changes
4. Use multiple browser tabs to test real-time features

## 📋 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 Kavish Shah

### Disclaimer

Kosh is designed for educational purposes and internal LAN use. It should not be exposed to the public internet without proper security hardening, including:

- HTTPS/TLS encryption
- Reverse proxy configuration
- Network firewall rules
- Regular security audits
- Strong authentication mechanisms

The authors are not responsible for any data loss, security breaches, or other issues arising from the use of this software.

## 🙏 Acknowledgments

Special thanks to all contributors who have helped make Kosh better:

- **Real-time features implementation**: WebSocket integration for live updates
- **Modular architecture**: Dashboard restructuring and component-based design
- **Security enhancements**: Encryption implementation and audit logging
- **Documentation improvements**: Comprehensive README and issue templates
- **Bug fixes and testing**: Community feedback and contributions

### Technologies & Libraries

- **Flask**: Web framework foundation
- **Flask-SocketIO**: Real-time WebSocket communication
- **cryptography**: Robust encryption library
- **Tailwind CSS**: Modern, responsive UI design
- **Socket.IO**: Client-side WebSocket library

### Inspiration

Kosh was created as a capstone project to demonstrate:

- Secure file sharing without cloud dependency
- Attribute-based access control concepts
- Real-time web application architecture
- Modern web development practices



## 📞 Support

For questions, bug reports, or feature requests:

- Create an issue on GitHub using our templates
- Check existing issues for similar problems
- Join discussions in existing issues

## 💡 Common Use Cases

### Example 1: Department-Based File Sharing

**Scenario:** Share financial reports only with finance and executive teams

1. Create attributes: `finance`, `executive`
2. Create users:
   - John (finance department): attributes = `finance`
   - Sarah (CEO): attributes = `executive, finance`
3. Upload report with policy: `finance, executive`
4. Result: Both John and Sarah can access the file

### Example 2: Project-Based Access Control

**Scenario:** Share project files with team members

1. Create attributes: `project_alpha`, `engineering`, `design`
2. Upload design files with policy: `project_alpha, design`
3. Upload code files with policy: `project_alpha, engineering`
4. Only users with both project_alpha AND the respective attribute can access

### Example 3: Role Manager Delegation

**Scenario:** HR manager needs to assign attributes to employees

1. Admin assigns `role_manager` role to HR user
2. HR user can now assign attributes to other users
3. HR user cannot add/remove global attributes (admin only)
4. All changes logged in audit trail

## 🔧 Troubleshooting

### Application Won't Start

**Problem:** `ModuleNotFoundError` or import errors

**Solution:**
```bash
# Ensure you're in the virtual environment
source venv/bin/activate  # On macOS/Linux
venv\Scripts\activate     # On Windows

# Reinstall dependencies
pip install -r requirements.txt
```

### Can't Access from Other Devices

**Problem:** Application only accessible from localhost

**Solution:**

- Ensure `KOSH_HOST=0.0.0.0` (binds to all interfaces)
- Check firewall settings allow port 7130
- Connect from device on same network: `http://<server-ip>:7130`

### File Upload Fails

**Problem:** Large file uploads fail or timeout

**Solution:**

- Check file size is under limit (default: 5GB)
- Ensure sufficient disk space in `app/uploads/`
- Check file extension is in `ALLOWED_EXTENSIONS`

### WebSocket Disconnections

**Problem:** Real-time updates stop working

**Solution:**

- Check browser console for WebSocket errors
- Refresh the page to reconnect
- Verify network stability
- Check if reverse proxy is configured for WebSocket support

### Audit Logs Growing Too Large

**Problem:** `audit_logs.jsonl` consuming too much disk space

**Solution:**

- Adjust `KOSH_AUDIT_RETENTION_DAYS` to shorter period
- Wait for automatic cleanup (runs every 24 hours)
- Manually delete old entries (backup first)

### Password Reset

**Problem:** Forgot admin password

**Solution:**

1. Edit `data/users.json`
2. Change admin password to default:
   ```json
   {
     "admin": {
       "attributes": [],
       "password": "pass"
     }
   }
   ```
3. Restart application
4. Login with `admin` / `pass`
5. Change password immediately

### Permission Denied Errors

**Problem:** Can't create files in `data/` or `app/uploads/`

**Solution:**
```bash
# Fix directory permissions
chmod 755 data/
chmod 755 app/uploads/
```

### Real-Time Features Not Working

**Problem:** Admin dashboard doesn't update in real-time

**Solution:**

- Open browser developer tools, check for JavaScript errors
- Verify WebSocket connection in Network tab
- Clear browser cache and reload
- Check if browser supports WebSocket (all modern browsers do)



## 🚀 Future Roadmap

Planned enhancements for future versions:

### Real-Time Features

- [ ] Real-time file upload progress indicators with percentage
- [ ] Live user activity indicators (who's online, what they're doing)
- [ ] Real-time system health monitoring (disk space, memory usage)
- [ ] Push notifications for critical events
- [ ] File download progress tracking
- [ ] Real-time file preview for supported formats

### Security Enhancements

- [ ] Two-factor authentication (2FA) support
- [ ] Cryptographic ABE implementation (replacing simulation)
- [ ] End-to-end encryption for file keys
- [ ] Password strength requirements and validation
- [ ] Session timeout and automatic logout
- [ ] IP-based access control
- [ ] Rate limiting for API endpoints
- [ ] Advanced RBAC with custom roles

### User Experience

- [ ] Advanced filtering with real-time updates
- [ ] Search functionality for files and users
- [ ] File tagging and categorization
- [ ] Favorites/starred files
- [ ] File sharing links with expiration
- [ ] Drag-and-drop file upload
- [ ] Batch file operations
- [ ] File versioning and history

### Administration

- [ ] User groups for easier attribute management
- [ ] Policy templates for common access patterns
- [ ] Scheduled policy expiration
- [ ] User import/export (CSV, JSON)
- [ ] Advanced audit reporting with charts
- [ ] Email notifications for admin events
- [ ] Backup and restore functionality
- [ ] Multi-admin support with granular permissions

### Technical Improvements

- [ ] Database backend option (SQLite, PostgreSQL)
- [ ] Docker containerization
- [ ] Kubernetes deployment support
- [ ] RESTful API with OpenAPI documentation
- [ ] GraphQL API for flexible queries
- [ ] CLI tool for administration
- [ ] Unit and integration tests
- [ ] Performance benchmarking

### Mobile & Accessibility

- [ ] Enhanced mobile responsiveness
- [ ] Progressive Web App (PWA) features
- [ ] Native mobile app (iOS/Android)
- [ ] Offline support for file listing
- [ ] Accessibility improvements (WCAG 2.1 AA compliance)
- [ ] Dark mode theme
- [ ] Multi-language support (i18n)

### File Management

- [ ] File preview for images, PDFs, documents
- [ ] Thumbnail generation for images/videos
- [ ] File compression before encryption
- [ ] Deduplication to save storage
- [ ] Automatic file expiration
- [ ] File size quotas per user
- [ ] Advanced MIME type detection

### Integration & Extensibility

- [ ] LDAP/Active Directory integration
- [ ] OAuth2/SAML authentication
- [ ] Webhook support for external integrations
- [ ] Plugin system for custom features
- [ ] External storage backends (S3, Azure Blob)
- [ ] Virus scanning integration (ClamAV)
- [ ] Analytics and reporting dashboard

### Developer Tools

- [ ] Comprehensive API documentation
- [ ] SDK for Python, JavaScript, Go
- [ ] Terraform provider for infrastructure as code
- [ ] Developer documentation and examples
- [ ] Contribution guidelines and templates
- [ ] Automated deployment scripts

---

**Contributions welcome!** If you'd like to work on any of these features, please create an issue or submit a pull request.

---

**Happy file sharing with Kosh! 🔐📁**

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

## 🌐 Features

### Core Features
- 🔒 **AES-encrypted file uploads and downloads** with robust encryption
- 🧑‍💻 **User-based attribute system** for granular access control
- 🔐 **Simulated ABE access control** using JSON policies
- 🎛️ **Admin dashboard** for managing users, attributes, and file policies
- 💡 **Modern Tailwind CSS UI** for all pages with responsive design
- 📁 **No cloud dependency** – works entirely on LAN
- 📊 **File policies with metadata** (policy, key, uploader, timestamp)

### Real-Time Features
- 🔄 **Live synchronization** across all admin sessions using WebSocket
- 📱 **Toast notifications** for user feedback
- 🌐 **Auto-reconnection** and connection status indicators
- 📝 **Live audit logs** for all system activities
- ⚡ **Bulk operations** with real-time updates

### Security Features
- 🔐 **AES-256 encryption** for all file operations
- 🛡️ **Attribute-based access control** with flexible policies
- 👥 **User authentication** with session management
- 🔍 **Audit logging** for all administrative actions
- 🚫 **CSRF protection** and input validation

## 📁 Project Structure

```
kosh/
├── app/
│   ├── app.py                      # Main Flask application
│   ├── __init__.py                 # Package initialization
│   ├── attribute_management.py     # Attribute management logic
│   ├── crypto/
│   │   ├── aes.py                  # AES encryption/decryption
│   │   └── abe_simulator.py        # JSON-based ABE simulation
│   ├── static/
│   │   ├── admin/                  # Admin dashboard assets
│   │   │   ├── admin.css
│   │   │   ├── admin-dashboard.js
│   │   │   └── tailwind.config.js
│   │   ├── dashboard/              # User dashboard assets
│   │   │   ├── dashboard.css
│   │   │   ├── dashboard.js
│   │   │   └── dashboard-tailwind.config.js
│   │   ├── shared/                 # Shared components and utilities
│   │   │   ├── components/
│   │   │   │   ├── modal.js
│   │   │   │   ├── notification-manager.js
│   │   │   │   └── toast.js
│   │   │   ├── modules/
│   │   │   │   ├── attribute-manager.js
│   │   │   │   ├── audit-manager.js
│   │   │   │   ├── dashboard-file-manager.js
│   │   │   │   ├── file-manager.js
│   │   │   │   ├── password-manager.js
│   │   │   │   ├── policy-manager.js
│   │   │   │   ├── realtime-manager.js
│   │   │   │   ├── upload-manager.js
│   │   │   │   └── user-manager.js
│   │   │   └── utils/
│   │   │       ├── admin-links.js
│   │   │       └── ui-helpers.js
│   │   └── common/                 # Common assets (icons, favicons)
│   ├── templates/
│   │   ├── index.html              # Login page
│   │   ├── dashboard.html          # User dashboard
│   │   └── admin.html              # Admin dashboard
│   ├── uploads/                    # Encrypted file storage
│   └── user_keys/                  # User key files
├── data/
│   ├── aes_encryption.key          # AES encryption key
│   ├── aes_hmac.key               # HMAC key for integrity
│   ├── attributes.json            # Global attribute pool
│   ├── audit_logs.jsonl           # System audit logs
│   ├── policies.json              # File access policies
│   └── users.json                 # User accounts and attributes
├── .github/                       # GitHub templates and workflows
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md
│       └── feature_request.md
├── requirements.txt               # Python dependencies
└── README.md                      # This file
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

### 3. Run the Application
```bash
python -m app.app
```

The application will start on `http://localhost:7130`. You can access it from any device on the same local network.

### 4. Default Login Credentials
- **Admin User**: `admin` / `pass`
- **Regular Users**: Default password is `pass` for all users

### 5. Admin Dashboard Access
- Navigate to `http://localhost:7130/admin` after logging in as admin
- Manage users, attributes, and file policies
- View real-time audit logs and system activity

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

### Encryption
- **AES-256 encryption** for all uploaded files
- **HMAC verification** for data integrity
- **Secure key management** with separate key files

### Access Control
- **Attribute-Based Encryption (ABE)** simulation using JSON policies
- **Role-based permissions** (admin vs regular users)
- **Session-based authentication** with Flask sessions

### Security Features
- All user inputs are validated and sanitized
- File uploads are encrypted before storage
- Admin operations require proper authentication
- WebSocket connections validate user sessions

### Default Password Implementation
All users have a consistent password structure:
- **Default password**: `pass` for all users
- **Backward compatibility** with legacy user formats
- **Secure password change** functionality

The system automatically converts legacy user formats to the new dictionary format:
```json
{
  "username": {
    "attributes": ["attr1", "attr2"],
    "password": "pass"
  }
}
```

### Reporting Security Vulnerabilities
Please report security vulnerabilities by creating an issue with the "security" label. We support the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | ✅ |
| 5.0.x   | ❌ |
| 4.0.x   | ✅ |
| < 4.0   | ❌ |

Include in your report:
- Clear description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested mitigation if known

## 🏗️ Architecture

### Modular Design
Kosh follows a modular architecture with clear separation of concerns:

#### Backend (Flask)
- **app.py**: Main application with routes and WebSocket handlers
- **crypto/**: Encryption and ABE simulation modules
- **attribute_management.py**: Centralized attribute operations

#### Frontend (JavaScript)
- **Modular Components**: Reusable UI components (modals, notifications)
- **Feature Modules**: Specialized modules for file management, uploads, etc.
- **Real-time Manager**: WebSocket connection and event handling

#### Data Layer
- **JSON-based storage**: Simple file-based data persistence
- **Structured policies**: Metadata-rich file access policies
- **Audit logging**: Comprehensive activity tracking

### Dashboard Restructuring
The dashboard has been completely restructured for better maintainability:

#### Key Improvements
- **Separated concerns**: CSS, JavaScript, and HTML in separate files
- **Component-based structure**: Reusable components and modules
- **Performance optimizations**: Better caching and loading strategies
- **Modular architecture**: Independent module development

#### File Organization
```
app/static/
├── css/
│   └── dashboard.css                    # All dashboard styles
├── js/
│   ├── dashboard.js                     # Main dashboard controller
│   ├── config/
│   │   └── dashboard-tailwind.config.js # Tailwind configuration
│   ├── components/
│   │   └── notification-manager.js     # Notification system
│   └── modules/
│       ├── dashboard-file-manager.js   # File display and management
│       ├── upload-manager.js           # File upload functionality
│       └── password-manager.js         # Password change modal
```

#### Benefits Achieved
- ✅ **Maintainability**: Easier to locate and modify specific functionality
- ✅ **Performance**: Better caching and reduced inline scripts
- ✅ **Scalability**: Easy to add new features and components
- ✅ **Developer Experience**: Better code readability and debugging

## 💻 Development

### Code Style Guidelines
- **Python**: Follow PEP8 standards
- **JavaScript**: Use ES6+ features, modular architecture
- **CSS**: Use Tailwind classes, organized structure
- **HTML**: Semantic HTML5 elements with proper ARIA attributes

### Adding New Features

#### Backend Real-Time Events
```python
# Emit events after data changes
socketio.emit('custom_event', data, room='admin_updates')
```

#### Frontend Event Handling
```javascript
// Listen for events and update UI
socket.on('custom_event', function(data) {
    updateUIElement(data);
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

### Future Enhancement Opportunities
With the new modular structure, future improvements are easier:
- ✅ Unit testing individual modules
- ✅ Adding new file management features
- ✅ Implementing additional upload options
- ✅ Enhanced accessibility features
- ✅ Performance optimizations
- ✅ Theme customization

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

This project is licensed for educational and internal LAN use only.

### Disclaimer
Kosh is designed for educational purposes and internal network use. It should not be exposed to the public internet without proper security hardening.

---

## 🙏 Acknowledgments

Thank you to all contributors who have helped make Kosh better:
- Contributors to the real-time features implementation
- Dashboard restructuring and modular architecture improvements
- Security enhancements and bug fixes
- Documentation improvements and issue templates

## 📞 Support

For questions, bug reports, or feature requests:
- Create an issue on GitHub using our templates
- Check existing issues for similar problems
- Join discussions in existing issues

## 🚀 Future Roadmap

Planned enhancements for future versions:
- [ ] Real-time file upload progress indicators
- [ ] Live user activity indicators
- [ ] Real-time system health monitoring
- [ ] Push notifications for critical events
- [ ] Advanced filtering with real-time updates
- [ ] Enhanced mobile responsiveness
- [ ] Multi-language support
- [ ] Advanced audit reporting
- [ ] API endpoints for external integrations
- [ ] Enhanced encryption options

---

**Happy file sharing with Kosh! 🔐📁**

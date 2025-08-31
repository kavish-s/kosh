# Kosh - LAN-Based Secure File Sharing with Simulated ABE

**Kosh** is a modern Flask application for secure file sharing over a local network using AES encryption and simulated Attribute-Based Encryption (ABE). It features a beautiful Tailwind-based UI, an admin dashboard for user and policy management, and improved file structure for scalability.

## 🌐 Features

- 🔒 AES-encrypted file uploads and downloads
- 🧑‍💻 User-based attribute system
- 🔐 Simulated ABE access control using JSON policies
- �️ Admin dashboard for managing users, attributes, and file policies
- 💡 Modern Tailwind CSS UI for all pages
- 📁 No cloud dependency – works entirely on LAN
- 📊 File policies now support metadata (policy, key, uploader, etc.)

## 📁 Project Structure

```
[project_root]/
├── app.py
├── crypto/
│   ├── aes.py               # AES encryption logic
│   └── abe_simulator.py     # JSON-based ABE simulation
├── static/
│   └── style.css            # Optional CSS
├── templates/
│   ├── index.html           # Login page
│   ├── dashboard.html       # Upload/download page
│   └── admin.html           # Admin dashboard (manage users/policies)
│   └── admin_add_user.html  # Add user form
│   └── admin_edit_user.html # Edit user form
│   └── admin_add_policy.html # Add policy form
│   └── admin_edit_policy.html # Edit policy form
├── uploads/                 # Stores encrypted files
├── data/
│   ├── users.json           # Maps users to attributes
│   └── policies.json        # Maps files to access policies (with metadata)
├── requirements.txt         # Python dependencies
└── README.md
```

## 🚀 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/kosh.git
cd kosh
```

### 2. Set Up Virtual Environment
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Run the App
```bash
python app.py
```

Visit `http://localhost:5000` or the server IP from another device on the same LAN.


### 4. Admin Dashboard & User Management
- Log in as `admin` to access the admin dashboard (`/admin`).
- Add, edit, or delete users and their attributes directly from the UI.

### 5. Policy Management
- Add, edit, or delete file access policies from the admin dashboard.
- Policies now use comma-separated attributes (e.g., `student,batch1`).
- Each file policy can include metadata (e.g., key, uploader, timestamp).

### 6. Uploading & Downloading Files
- Log in as any user.
- Upload files with custom access policies.
- Download files if your attributes match the policy.

### 7. File Structure & Metadata
- `data/policies.json` now stores policies as objects:
```json
{
  "file1.pdf.enc": {"policy": "student,batch1", "key": "...", "uploaded_by": "admin"}
}
```

## 📋 License
This project is for educational and internal LAN use only.

---
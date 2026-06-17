# Secure Cloud Data Vault

Secure Cloud Data Vault is a production-ready, lightweight, and highly secure cloud web application designed to protect sensitive user information. Built using **Python Flask, MySQL, Bootstrap 5, and vanilla JavaScript**, the application incorporates a Double-Layer Security Protocol to defend against web attacks and secure data cryptographically.

It is designed to run locally for testing (with a seamless automatic fallback to SQLite) and is optimized for deployment on the AWS EC2 Free Tier.

---

## 🛠️ Technology Stack
*   **Backend:** Python Flask
*   **Database:** MySQL (Main Target), SQLite (Local Fallback)
*   **Database ORM:** Flask-SQLAlchemy (parameterized queries)
*   **Cryptography:** `cryptography` library (AES-256-GCM authenticated encryption for sensitive info)
*   **Hashing:** Werkzeug Security (PBKDF2/scrypt password hashing)
*   **CSRF Protection:** Flask-WTF CSRFProtect (form tokens and header validation)
*   **Frontend:** HTML5, CSS3 (Vanilla Custom Theme), Bootstrap 5, JavaScript (Vanilla ES6)
*   **Charts:** Chart.js (Interactive security graphics)
*   **WSGI Server:** Gunicorn (for Linux/AWS production)

---

## 📁 Folder Structure
The project maintains a clean, modular structure:

```text
Secure-Cloud-Data-Vault/
│
├── app.py                  # Main Flask application router, models, and endpoints
├── encryption.py           # Cryptographic module (AES-256-GCM encrypt/decrypt utilities)
├── security.py             # Security Engine (SQLi detection, validators, capability RBAC)
├── config.py               # Flask and database environment configurations
├── database.sql            # MySQL schema creation and initial privilege seeding
├── requirements.txt        # Python package dependencies
├── README.md               # Main project documentation
├── deployment_guide.md     # Step-by-step AWS EC2 deployment manual
│
├── templates/              # HTML templates (Jinja2)
│   ├── base.html           # Main UI navbar, layout, and footer structure
│   ├── index.html          # Landing page (and Layer 1 SQLi warning block screen)
│   ├── register.html       # User register page with live password strength check
│   ├── login.html          # User login page with secure session warnings
│   ├── profile.html        # User profile & interactive cryptographic sandbox
│   └── dashboard.html      # Admin Security Dashboard with metrics, charts, & CSV export
│
├── static/                 # Static asset resources
│   ├── css/
│   │   └── style.css       # Custom premium glowing dark cybersecurity theme
│   ├── js/
│   │   └── main.js         # AJAX submissions, log search, & Chart.js setup
│   └── images/             # Image directory
│
└── instance/               # Auto-created directory for local SQLite DB & keys
    ├── secret.key          # Auto-generated 256-bit AES cryptographic key
    └── secure_vault.db     # Auto-created SQLite DB (if MySQL is unavailable)
```

---

## 🔒 Security Architecture (Double Layer Protocol)

### 🛡️ Layer 1: Input Validation & Threat Interception
Layer 1 acts as the firewall. The application registers a pre-request hook that scans all input channels (`request.args`, `request.form`, `request.json`) before they reach database operations.
*   **SQL Injection Detection Engine:** Uses regular expressions to match structural signatures such as:
    *   SQL comment indicators (`--`, `#`, `/*`)
    *   Trivial boolean comparisons (e.g. `OR 1=1`)
    *   Structural keywords (`UNION SELECT`, `DROP TABLE`, `DELETE FROM`, `INSERT INTO`, `EXEC`, `xp_cmdshell`)
    *   *Note: Single quote (`'`) characters alone are allowed to avoid false positives on user names or text inputs, but structural SQL uses involving quotes are caught.*
*   **Request Blocking:** If a pattern is matched, the engine logs the event, flags the source IP, and terminates the request with a **403 Forbidden** warning screen.
*   **Format Verification:** Validates email formatting (regex) and enforces password complexity rules (minimum 8 characters, uppercase, lowercase, digit, and special symbol).
*   **HTML Sanitization:** Escapes HTML strings to mitigate Cross-Site Scripting (XSS).

### 🔑 Layer 2: Cryptographic Data Protection & Session Security
Layer 2 protects data at rest and secures user sessions.
*   **Werkzeug Password Hashing:** User master passwords are hashed securely using industry-standard salted hashing algorithms (PBKDF2/scrypt). Plaintext passwords are never stored or exposed to database logs.
*   **AES-256-GCM Encryption:** Sensitive user notes and configuration details are encrypted using Advanced Encryption Standard in Galois/Counter Mode (GCM).
    *   **Galois/Counter Mode:** Unlike standard CBC, GCM produces an authentication tag. If ciphertext is tampered with in the database, decryption fails immediately.
    *   **Key Isolation:** The 256-bit key is generated securely and stored in `instance/secret.key`. This file should be kept out of version control.
*   **Flask-WTF CSRF Protection:** All state-changing requests (forms and API endpoints using POST) require valid Cross-Site Request Forgery tokens. Form submissions include a hidden CSRF field, and AJAX operations retrieve the token from the page metadata and pass it in the `X-CSRFToken` request header.
*   **Access Control & Capability Codes (RBAC):** Admin endpoints are protected by capability checks:
    *   `ADMIN_ACCESS` - Grants access to the security dashboard page and decryption operations.
    *   `VIEW_USERS` - Allows retrieving the list of registered users.
    *   `VIEW_LOGS` - Allows viewing security threat logs.
    *   `DELETE_RECORDS` - Permits deleting database history.
*   **Session Security:** 
    *   *Session Lifetime:* Capped at 15 minutes of inactivity; cookies are cleared on timeout.
    *   *Cookie Flags:* `HTTPOnly` prevents JavaScript access; `SameSite=Lax` mitigates CSRF; `Secure` enforces HTTPS.

---

## 🚀 Getting Started Locally

### 1. Prerequisites
Ensure you have **Python 3.10+** installed. If you wish to use the MySQL engine locally, ensure a local MySQL server is running.

### 2. Installation
Clone or download the project files, navigate to the directory, and install the dependencies:
```bash
pip install -r requirements.txt
```

### 3. Running the App
Run the Flask server:
```bash
python app.py
```

#### 💡 Automatic SQLite Fallback
If the application cannot connect to the default MySQL configuration (configured in `config.py`), it prints a warning to the console and automatically initializes a local **SQLite database** inside the `instance/` folder. This ensures you can evaluate the project immediately without configuring a local MySQL database.

To force SQLite, set `USE_SQLITE=True` in your environment:
```powershell
$env:USE_SQLITE="True"
python app.py
```

### 4. Default Credentials
The application automatically seeds a default administrator account on startup:
*   **Email:** `admin@securevault.local`
*   **Password:** `VaultAdmin2026!`
*   *Capabilities Mapped:* `ADMIN_ACCESS`, `VIEW_USERS`, `VIEW_LOGS`, `DELETE_RECORDS`

---

## 📊 Testing & Verification
We have included a testing suite inside the `scratch/` directory:
```bash
python scratch/verify_security.py
```
This script runs unit checks directly on the cryptographic, hashing, and regex engines to verify that passwords, emails, encryption, and SQLi signatures are correctly caught.

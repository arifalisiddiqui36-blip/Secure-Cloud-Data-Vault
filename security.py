# Secure Cloud Data Vault - Security Engine Module
# This module implements the Double Layer Security Protocol.
# Layer 1: Input Validation, SQL Injection (SQLi) Detection, Sanitization, Email/Password Validation
# Layer 2: Access Control, Capability-based Authorization decorator, and attack logging.

import re
import html
import sys
from functools import wraps
from flask import request, session, flash, redirect, url_for, jsonify

# -----------------------------------------------------
# LAYER 1: INPUT VALIDATION & SQLi DETECTION
# -----------------------------------------------------

# Compilation of regular expressions for detecting SQL injection payloads.
# These match common SQL syntax, functions, comments, and injection patterns.
SQLI_PATTERNS = [
    # 1. Comment patterns: --, /*, # (often used to truncate queries)
    (re.compile(r'--'), "SQL Comment (--)"),
    (re.compile(r'/\*'), "SQL Block Comment (/*)"),
    (re.compile(r'#'), "SQL Hash Comment (#)"),
    
    # 2. Trivial OR conditions: OR 1=1, OR 'a'='a', OR true (used to bypass authentication)
    (re.compile(r'\bOR\s+[\w\d\'"]+\s*=\s*[\w\d\'"]+\b', re.IGNORECASE), "SQL Trivial OR Condition (OR 1=1)"),
    
    # 3. SELECT and UNION injection: UNION SELECT, UNION ALL SELECT
    (re.compile(r'\bUNION\s+(ALL\s+)?SELECT\b', re.IGNORECASE), "SQL UNION SELECT Attack"),
    
    # 4. Data Definition Language (DDL): DROP TABLE, ALTER TABLE, CREATE TABLE
    (re.compile(r'\bDROP\s+TABLE\b', re.IGNORECASE), "SQL DROP TABLE command"),
    
    # 5. Data Manipulation Language (DML): DELETE FROM, INSERT INTO, UPDATE SET
    (re.compile(r'\bDELETE\s+FROM\b', re.IGNORECASE), "SQL DELETE FROM command"),
    (re.compile(r'\bINSERT\s+INTO\b', re.IGNORECASE), "SQL INSERT INTO command"),
    (re.compile(r'\bUPDATE\s+.*\s+SET\b', re.IGNORECASE), "SQL UPDATE SET command"),
    
    # 6. Command execution and stored procedures: xp_cmdshell, EXEC, EXECUTE
    (re.compile(r'\bxp_cmdshell\b', re.IGNORECASE), "SQL xp_cmdshell command execution attempt"),
    (re.compile(r'\bEXEC(UTE)?\b', re.IGNORECASE), "SQL EXEC command execution attempt"),
    
    # 7. Inline queries / SELECT statement hijacking
    (re.compile(r'\bSELECT\s+.*\s+FROM\b', re.IGNORECASE), "SQL SELECT FROM query injection")
]

def detect_sql_injection(input_value: str) -> tuple[bool, str | None]:
    """
    Scans a string input for known SQL Injection patterns.
    Returns (True, pattern_name) if a match is found, otherwise (False, None).
    """
    if not input_value or not isinstance(input_value, str):
        return False, None

    # Check the input value against each compiled regular expression
    for pattern, pattern_name in SQLI_PATTERNS:
        if pattern.search(input_value):
            return True, pattern_name
            
    return False, None

def sanitize_input(input_value: str) -> str:
    """
    Sanitizes string inputs to prevent Cross-Site Scripting (XSS).
    It strips leading/trailing whitespaces and escapes HTML characters.
    """
    if not input_value or not isinstance(input_value, str):
        return input_value
    
    # Trim whitespace
    cleaned = input_value.strip()
    # Escape HTML tags (e.g. converting <script> to &lt;script&gt;)
    return html.escape(cleaned)

def validate_email(email: str) -> bool:
    """
    Validates email syntax using a standard RFC 5322 regex pattern.
    """
    if not email:
        return False
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_regex, email))

def validate_password(password: str) -> tuple[bool, str]:
    """
    Validates password complexity rules for enhanced user account security.
    Rules:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if not password:
        return False, "Password cannot be empty."
        
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
        
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
        
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
        
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."
        
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character (e.g., !@#$%^&*)."
        
    return True, ""


# -----------------------------------------------------
# LAYER 2: DATA PROTECTION & ACCESS CONTROL
# -----------------------------------------------------

def log_attack_attempt(input_data: str, attack_type: str, ip_address: str):
    """
    Saves an attack record to the database log.
    Uses lazy import to avoid circular dependencies with app.py.
    """
    app_module = _get_app_module()
    if not app_module or not hasattr(app_module, 'AttackLog'):
        print("Failed to log security attack: application module not available.")
        return

    from flask import current_app
    db = current_app.extensions['sqlalchemy']
    AttackLog = app_module.AttackLog
    try:
        log_entry = AttackLog(
            input_data=input_data,
            attack_type=attack_type,
            ip_address=ip_address,
            status="Blocked"
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        print(f"Failed to log security attack: {str(e)}")


def _get_app_module():
    """Return the loaded application module (app.py may run as __main__)."""
    return sys.modules.get('app') or sys.modules.get('__main__')


def _is_api_request() -> bool:
    """True when the client expects a JSON API response."""
    return request.path.startswith('/api/') or request.headers.get('X-Requested-With') == 'XMLHttpRequest'


def require_capability(required_capability_name: str):
    """
    Custom decorator to enforce capability-based authorization (Layer 2 Access Control).
    It checks if the logged-in user has the specific capability code mapped in the database.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                if _is_api_request():
                    return jsonify({"status": "Error", "message": "Authentication required."}), 401
                flash("Authentication required. Please login first.", "danger")
                return redirect(url_for('login_page'))

            # Resolve models from the already-loaded app module to avoid
            # circular import / duplicate SQLAlchemy instance issues.
            app_module = _get_app_module()
            if not app_module or not hasattr(app_module, 'User'):
                if _is_api_request():
                    return jsonify({"status": "Error", "message": "Server configuration error."}), 500
                flash("Server configuration error.", "danger")
                return redirect(url_for('home_page'))

            User = app_module.User
            user = User.query.get(session['user_id'])
            if not user:
                session.clear()
                if _is_api_request():
                    return jsonify({"status": "Error", "message": "Invalid session. Please login again."}), 401
                flash("Session invalid. Please login again.", "danger")
                return redirect(url_for('login_page'))

            has_capability = any(
                cap.code_name == required_capability_name
                for cap in user.capabilities
            )

            if not has_capability:
                log_attack_attempt(
                    input_data=f"User ID {user.id} tried to perform admin action requiring: {required_capability_name}",
                    attack_type=f"Unauthorized Capability Access: {required_capability_name}",
                    ip_address=request.remote_addr
                )

                if _is_api_request():
                    return jsonify({
                        "status": "Error",
                        "message": f"Access Denied: Missing capability {required_capability_name}"
                    }), 403

                flash(
                    f"Access Denied: You do not have the required capability code ({required_capability_name}) to perform this action.",
                    "danger"
                )
                return redirect(url_for('home_page'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

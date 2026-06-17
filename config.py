# Secure Cloud Data Vault - Configuration Module
# This module defines the setup for database connectivity, security sessions, and file locations.

import os
from datetime import timedelta

class Config:
    # -----------------------------------------------------
    # Security Configuration
    # -----------------------------------------------------
    # Secret key for signing Flask session cookies. 
    # In production, this must be a random, secret string.
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cyber_secure_data_vault_2026_super_secret_key')

    # Session timeout configuration (Double Layer Security - Layer 2)
    # Automatically log out users after 15 minutes of inactivity.
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)

    # Session Cookie Security flags:
    # HTTPOnly: True prevents client-side scripts (JS) from accessing cookies, mitigating XSS attacks.
    SESSION_COOKIE_HTTPONLY = True
    # SameSite: 'Lax' helps prevent Cross-Site Request Forgery (CSRF) attacks.
    SESSION_COOKIE_SAMESITE = 'Lax'
    # Secure: True requires HTTPS. Set to False for local dev, but should be True on AWS with SSL.
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1')

    # -----------------------------------------------------
    # Encryption Configurations
    # -----------------------------------------------------
    # Base directory of the application
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    
    # Instance folder path (Flask default directory for instance-specific files like SQLite DB and keys)
    INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
    os.makedirs(INSTANCE_DIR, exist_ok=True)

    # Path to store the generated AES-256 key
    # Updated: Now stored inside the instance/ directory as requested
    KEY_FILE_PATH = os.path.join(INSTANCE_DIR, 'secret.key')

    # -----------------------------------------------------
    # Database Configuration
    # -----------------------------------------------------
    # MySQL configurations (Main target for production / AWS EC2 deployment)
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_NAME = os.environ.get('DB_NAME', 'secure_vault')
    
    # Check if we should force SQLite for local development out-of-the-box
    FORCE_SQLITE = os.environ.get('USE_SQLITE', 'False').lower() in ('true', '1')
    
    if FORCE_SQLITE:
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(INSTANCE_DIR, 'secure_vault.db')}"
    else:
        # Construct MySQL connection string using PyMySQL
        SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
    
    # Disable tracking modifications to save system resources
    SQLALCHEMY_TRACK_MODIFICATIONS = False

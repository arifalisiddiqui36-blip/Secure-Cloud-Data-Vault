-- Secure Cloud Data Vault - Database Schema Creation Script
-- Target Database: MySQL
-- Purpose: Security database setup including users, capability authorization codes, and attack logs.

-- Create database if it does not exist
CREATE DATABASE IF NOT EXISTS secure_vault;
USE secure_vault;

-- -----------------------------------------------------
-- Table: users
-- Description: Stores user credentials and AES-256 encrypted sensitive info.
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    -- Hashed securely using PBKDF2/scrypt (Werkzeug hashing)
    password_hash VARCHAR(255) NOT NULL,
    -- Encrypted with AES-256 (Base64 encoded string containing ciphertext, nonce, tag)
    sensitive_info TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------
-- Table: capability_codes
-- Description: Stores authorization capabilities (e.g., VIEW_USERS, ADMIN_ACCESS).
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS capability_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    code_name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------
-- Table: user_capabilities
-- Description: Mapping table for Many-to-Many relationship between users and capability codes.
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS user_capabilities (
    user_id INT NOT NULL,
    capability_code_id INT NOT NULL,
    PRIMARY KEY (user_id, capability_code_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (capability_code_id) REFERENCES capability_codes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------
-- Table: attack_logs
-- Description: Stores records of blocked SQL Injection attacks and security warnings.
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    input_data TEXT,                   -- The exact malicious payload intercepted
    attack_type VARCHAR(100),          -- Category of attack (e.g. SQLi Pattern, Admin Access Bypass)
    ip_address VARCHAR(45),            -- IPv4 or IPv6 address of the source
    status VARCHAR(50),                -- Action taken (e.g. Blocked, Logged)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------
-- Initial Seeding of Capabilities
-- -----------------------------------------------------
INSERT INTO capability_codes (code_name, description) VALUES
('ADMIN_ACCESS', 'Access to the core Administrator Dashboard'),
('VIEW_USERS', 'Capability to view the list of registered users and security credentials'),
('VIEW_LOGS', 'Capability to inspect the security SQLi attack logs'),
('DELETE_RECORDS', 'Capability to delete/clear security logs')
ON DUPLICATE KEY UPDATE description=VALUES(description);

-- Note: User capabilities will be linked to created users. 
-- In our application startup (app.py), we will automatically check and seed 
-- a default administrator account: admin@securevault.local with password VaultAdmin2026!
-- and map all capability codes to it.

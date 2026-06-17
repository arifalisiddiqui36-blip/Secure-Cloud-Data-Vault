# Secure Cloud Data Vault - Encryption/Decryption Utility Module
# This module implements AES-256-GCM authenticated encryption for sensitive user data.
# In GCM (Galois/Counter Mode), the encryption produces a ciphertext and an authentication tag
# which guarantees both confidentiality and integrity of the stored data.

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from config import Config

# Initialize default backend for cryptography
backend = default_backend()

def get_or_create_key() -> bytes:
    """
    Loads the 256-bit encryption key from the secure location config.KEY_FILE_PATH.
    If the key file does not exist, it generates a cryptographically secure key,
    saves it to the file, and then returns the key bytes.
    """
    key_path = Config.KEY_FILE_PATH
    
    # Check if the key file already exists
    if os.path.exists(key_path):
        with open(key_path, 'r') as key_file:
            # Read key and decode the Base64 representation to get the raw bytes
            key_base64 = key_file.read().strip()
            return base64.b64decode(key_base64)
    else:
        # Generate a cryptographically secure 256-bit (32 bytes) key
        # os.urandom is safe for security/cryptographic use
        raw_key = os.urandom(32)
        key_base64 = base64.b64encode(raw_key).decode('utf-8')
        
        # Ensure the instance directory exists before writing
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        
        # Save the key separately (Double Layer Security - Layer 2)
        with open(key_path, 'w') as key_file:
            key_file.write(key_base64)
            
        return raw_key

def encrypt(plain_text: str) -> str:
    """
    Encrypts a string using AES-256-GCM.
    Returns a Base64-encoded string containing the combined nonce, tag, and ciphertext.
    """
    if not plain_text:
        return ""
        
    try:
        # Load the raw 256-bit key
        key = get_or_create_key()
        
        # Generate a unique 12-byte initialization vector (nonce) for GCM.
        # NEVER reuse a nonce with the same key in GCM mode.
        nonce = os.urandom(12)
        
        # Configure the AES-256 cipher in GCM mode
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend)
        encryptor = cipher.encryptor()
        
        # Encrypt the UTF-8 encoded plaintext
        ciphertext = encryptor.update(plain_text.encode('utf-8')) + encryptor.finalize()
        
        # The tag is a 16-byte authentication tag produced by GCM mode
        # to ensure the data is not tampered with
        tag = encryptor.tag
        
        # Pack nonce + tag + ciphertext together for easy storage in the database
        combined_payload = nonce + tag + ciphertext
        
        # Base64 encode the combined payload to store as text safely in MySQL
        return base64.b64encode(combined_payload).decode('utf-8')
        
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt(encrypted_text_b64: str) -> str:
    """
    Decrypts a Base64-encoded AES-256-GCM ciphertext.
    Verifies the integrity tag before returning the decrypted plaintext.
    """
    if not encrypted_text_b64:
        return ""
        
    try:
        # Load the raw 256-bit key
        key = get_or_create_key()
        
        # Base64 decode the stored encrypted value to get the combined payload
        combined_payload = base64.b64decode(encrypted_text_b64)
        
        # Unpack the payload:
        # - The first 12 bytes are the nonce
        # - The next 16 bytes are the authentication tag
        # - The remaining bytes are the actual ciphertext
        nonce = combined_payload[:12]
        tag = combined_payload[12:28]
        ciphertext = combined_payload[28:]
        
        # Configure the AES-256 cipher in GCM mode for decryption
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=backend)
        decryptor = cipher.decryptor()
        
        # Decrypt and verify tag. If the tag doesn't match (i.e. data tampered with),
        # an InvalidTag exception is thrown, preventing decryption.
        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        
        return decrypted_bytes.decode('utf-8')
        
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}. This might indicate data tampering or a key mismatch.")

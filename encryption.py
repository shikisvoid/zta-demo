import hashlib
import json
from cryptography.fernet import Fernet

class DataVault:
    def __init__(self):
        # AES-128 Encryption Key
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
    
    def _generate_hash(self, data: str) -> str:

        return hashlib.sha256(data.encode()).hexdigest()
    
    def encrypt(self, data: str) -> dict:

        # 1. Encrypt the data (Confidentiality)
        encrypted_bytes = self.cipher.encrypt(data.encode())
        
        # 2. Generate Hash (Integrity)
        data_hash = self._generate_hash(data)
        
        return {
            "ciphertext": encrypted_bytes.decode(), # Convert bytes to string for JSON
            "integrity_hash": data_hash,
            "algorithm": "AES-128-GCM + SHA-256"
        }
    
    def decrypt_and_verify(self, packet: dict) -> str:

        try:
            # 1. Decrypt
            encrypted_bytes = packet['ciphertext'].encode()
            decrypted_data = self.cipher.decrypt(encrypted_bytes).decode()
            
            # 2. Verify Integrity
            current_hash = self._generate_hash(decrypted_data)
            original_hash = packet['integrity_hash']
            
            if current_hash != original_hash:
                return f"[CRITICAL SECURITY ALERT] DATA INTEGRITY COMPROMISED! Hash mismatch.\n   Expected: {original_hash}\n   Calculated: {current_hash}"
                
            return decrypted_data
            
        except Exception as e:
            return f"[DECRYPTION_ERROR] {str(e)}"
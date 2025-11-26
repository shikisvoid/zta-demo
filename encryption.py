from cryptography.fernet import Fernet

class DataVault:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
    
    def encrypt(self, data: str) -> bytes:
        return self.cipher.encrypt(data.encode())
    
    def decrypt(self, token: bytes) -> str:
        try:
            return self.cipher.decrypt(token).decode()
        except Exception:
            return "[DECRYPTION_ERROR] Invalid Key"
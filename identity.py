from config import USERS_DB

class IdentityProvider:
    def authenticate_user(self, username, password):
        user = USERS_DB.get(username)
        if not user:
            return False, "User not found"
        
        if user["password"] == password:
            return True, user
        else:
            return False, "Invalid password"
    
    def verify_mfa(self, username, token):
        user = USERS_DB.get(username)
        if not user or not user["mfa_secret"]:
            return False
        
        if token == user["mfa_secret"]:
            return True
        return False
from config import USERS_DB
import secrets
import time

class IdentityProvider:
    def __init__(self):
        self.failed_attempts = {}
        self.MAX_ATTEMPTS = 3
        self.LOCKOUT_DURATION = 300

    def authenticate_user(self, username, password):
        user = USERS_DB.get(username)
        if not user:
            return False, "User not found"
    
        if self._is_locked_out(username):
            remaining = int(self.failed_attempts[username]['lockout_until'] - time.time())
            return False, f"Account Locked: Too many failed attempts. Try again in {remaining} seconds."

        if secrets.compare_digest(user["password"], password):
            self._reset_failures(username)
            return True, user
        else:
            self._record_failure(username)
            return False, "Invalid Password"
        
    def verify_mfa(self, username, token):
        user = USERS_DB.get(username)
        if not user or not user["mfa_secret"]:
            return False
        
        if token and secrets.compare_digest(str(token), str(user["mfa_secret"])):
            return True
        return False
    
    def _is_locked_out(self, username):
        if username not in self.failed_attempts:
            return False
        
        record = self.failed_attempts[username]

        if record['lockout_until'] > time.time():
            return True
        
        if record['lockout_until'] > 0 and record['lockout_until'] <= time.time():
            self._reset_failures(username)
        
        return False
    
    def _record_failure(self, username):
        if username not in self.failed_attempts:
            self.failed_attempts[username] = {'count': 0, 'lockout_until': 0}

        record = self.failed_attempts[username]
        record['count'] += 1

        if record['count'] >= self.MAX_ATTEMPTS:
            record['lockout_until'] = time.time() + self.LOCKOUT_DURATION

    def _reset_failures(self, username):
        if username in self.failed_attempts:
            del self.failed_attempts[username]
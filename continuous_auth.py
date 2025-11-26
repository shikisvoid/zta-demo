import time
import uuid
from advanced_zta import AccessRequest

SESSION_TIMEOUT_SECONDS = 30 * 60
IDLE_TIMEOUT_SECONDS = 5 * 50

class SessionManager:
    def __init__(self, risk_engine):
        self.sessions = {}
        self.risk_engine = risk_engine

    def create_session(self, user, role, device_id, current_context):
        session_id = str(uuid.uuid4())

        self.sessions[session_id] = {
            "user": user,
            "role": role,
            "device_id": device_id,
            "start_time": current_context['timestamp'],
            "last_active": current_context['timestamp'],
            "initial_ip": current_context.get('ip_address'),
            "is_active": True
        }

        return session_id
    
    def validate_session(self, session_id, context):

         # 1. Check if session exists
        if session_id not in self.sessions:
            return False, "Session Invalid or Expired"

        session = self.sessions[session_id]

        if not session['is_active']:
            return False, "Session previously revoked"

        current_time = context['timestamp']

        # 2. Check Absolute Timeout (Force re-login after 30 mins)
        if (current_time - session['start_time']) > SESSION_TIMEOUT_SECONDS:
            self.revoke_session(session_id)
            return False, "Session Token Expired (Max Duration Reached)"

        # 3. Check Idle Timeout (User walked away)
        if (current_time - session['last_active']) > IDLE_TIMEOUT_SECONDS:
            self.revoke_session(session_id)
            return False, "Session Expired due to Inactivity (Idle Timeout)"

        # 4. Detect Context Change (e.g., Session Hijacking / IP Spoofing)
        # If the IP changes mid-session, it's highly suspicious.
        current_ip = context.get('ip_address')
        if current_ip and current_ip != session['initial_ip']:
            self.revoke_session(session_id)
            return False, f"CRITICAL: IP Address changed mid-session ({session['initial_ip']} -> {current_ip}). Token Theft Suspected."

        # 5. Re-Run Risk Engine (Continuous Risk Assessment)
        # We construct a request object to check if the new action is risky
        req = AccessRequest(
            user=session['user'],
            role=session['role'],
            ip_address=current_ip,
            location=context.get('location', 'Unknown'),
            device_id=session['device_id'],
            resource_sensitivity=5, # Baseline check
            timestamp=current_time,
        )
        
        # Calculate new risk
        risk_score, reasons = self.risk_engine.calculate_risk(req)
        
        # If behavior suddenly becomes high risk (e.g., > 60), kill session
        if risk_score > 60:
            self.revoke_session(session_id)
            return False, f"Continuous Trust Revoked: Risk Score spiked to {risk_score} ({reasons})"

        # If all good, update last active time
        session['last_active'] = current_time
        return True, "Session Valid"
    
    def revoke_session(self, session_id):
        if session_id in self.sessions:
            self.sessions[session_id]['is_active'] = False
from config import NETWORK_SEGMENTS
from encryption import DataVault
import time
import random
from advanced_zta import AccessRequest, AdaptiveRiskEngine

class SecureAccessProxy:
    def __init__(self, identity_provider, device_manager):
        self.idp = identity_provider
        self.device_mgr = device_manager
        self.vault = DataVault()
        self.risk_engine = AdaptiveRiskEngine()
    
    def process_access_request(self, ctx):
        user = ctx['user']
        print(f"\n--- GATEWAY: Processing Request for {user} ---")

        # === PHASE 1: HARD SECURITY CHECKS (Must Pass) ===

        #Layer 1 : Identity
        is_auth, user_obj = self.idp.authenticate_user(user, ctx['password'])
        if not is_auth:
            return {"status": "DENIED", "reason": f"Identity Failed: {user_obj}"}
        
        #Layer 2: Device Posture
        is_healthy, health_reason = self.device_mgr.assess_posture(ctx['device_id'])
        if not is_healthy:
            return {"status": "DENIED", "reason": f"Device Posture Failed: {health_reason}"}
        
        #Layer 3: Micro-Segmentation(RBAC)
        allowed_roles = NETWORK_SEGMENTS.get(ctx['target_segment'], [])
        if user_obj['role'] not in allowed_roles:
            return {"status": "DENIED", "reason": f"Segmentation Violation: Role '{user_obj['role']} cannot access '{ctx['target_segment']}"}
        
        # === PHASE 2: ADAPTIVE RISK ANALYSIS ===

        req_ip = ctx.get('ip_address', "10.0.0.5") # Default to internal IP
        req_loc = ctx.get('location', "Hospital_Local")
        req_time = ctx.get('timestamp', time.time())

        sensitivity = 10 if ctx['target_segment'] == "EHR_CORE" else 5

        risk_req = AccessRequest(
            user=user,
            role=user_obj['role'],
            ip_address=req_ip,
            location=req_loc,
            device_id=ctx['device_id'],
            resource_sensitivity=sensitivity,
            timestamp=req_time
        )

        policy = self.risk_engine.enforce_policy(risk_req)

        if policy['decision'] == "BLOCK":
            return {"status": "DENIED", "reason": f"Risk Engine Blocked: {policy['msg']}"}

        elif policy['decision'] == "MFA_CHALLENGE":
            print(f"   >>> STEP-UP AUTH TRIGGERED (Score: {policy['score']}) - Validating MFA...")
            if not self.idp.verify_mfa(user, ctx.get('mfa')):
                 return {"status": "DENIED", "reason": "High Risk Access requires valid MFA"}
            print("   >>> MFA Validated. Proceeding.")
        
        
        # === PHASE 3: DATA PROTECTION ===

        encrypted_data = self.vault.encrypt(ctx['data'])
        return {
            "status": "GRANTED", 
            "reason": f"Authorized (Risk Score: {policy['score']})",
            "secure_payload": encrypted_data,
            "decrypted_view": ctx['data']
        }
from config import NETWORK_SEGMENTS, FIREWALL_RULES
from encryption import DataVault
import time
from continuous_auth import SessionManager
from advanced_zta import AccessRequest, AdaptiveRiskEngine, SIEMLogger

class SecureAccessProxy:
    def __init__(self, identity_provider, device_manager):
        self.idp = identity_provider
        self.device_mgr = device_manager
        self.vault = DataVault()
        self.logger = SIEMLogger(reset = True)
        self.risk_engine = AdaptiveRiskEngine(self.logger)
        self.session_mgr = SessionManager(self.risk_engine)
    
    def process_access_request(self, ctx):
        user = ctx['user']
        session_id = ctx.get('session_id')
        print(f"\n--- GATEWAY: Processing Request for {user} ---")

        # === PHASE 1: HARD SECURITY CHECKS (Must Pass) ===
        if session_id:
            print(f"\n--- GATEWAY: Validating Active Session ({session_id[:8]}...) ---")
            is_valid, msg = self.session_mgr.validate_session(session_id, ctx)
            
            if not is_valid:
                self.logger.log("SESSION_REVOKED", 100, {"user": user, "reason": msg})
                return {"status": "DENIED", "reason": msg}
            
            # If valid, pass through (Encryption phase)
            print(f"   >>> Continuous Trust Verified. {msg}")
            encrypted_data = self.vault.encrypt(ctx.get('data', ''))
            return {"status": "GRANTED", "reason": "Session Validated", "secure_payload": encrypted_data}

        #Layer 1 : Identity
        is_auth, user_obj = self.idp.authenticate_user(user, ctx['password'])
        if not is_auth:
            reason = f"Identity Failed: {user_obj}"
            self.logger.log("IDENTITY_BLOCK", 100, {"user": user, "reason": reason})
            return {"status": "DENIED", "reason": reason}
        
        #Layer 2: Device Posture
        is_healthy, health_reason = self.device_mgr.assess_posture(ctx['device_id'])
        if not is_healthy:
            reason = f"Device Posture Failed: {health_reason}"
            self.logger.log("DEVICE_BLOCK", 100, {"user": user, "device": ctx['device_id'], "reason": reason})
            return {"status": "DENIED", "reason": reason}
        
        #Layer 3: Micro-Segmentation(RBAC)
        target_segment = ctx['target_segment']
        allowed_roles = NETWORK_SEGMENTS.get(target_segment, [])
        if user_obj['role'] not in allowed_roles:
            reason = f"Role '{user_obj['role']}' not permitted in '{target_segment}'"
            self.logger.log("RBAC_BLOCK", 100, {"user": user, "role": user_obj['role'], "target": target_segment})
            return {"status": "DENIED", "reason": reason}
        
        #Layer 4: Firewall Based Micro-segmentation
        source_segment = "HOSPITAL_LOCAL"
        if "IoMT" in user_obj['role']: source_segment = "IOMT_VLAN"
        if ctx.get('location') != "Hospital_Local": source_segment = "PUBLIC_WIFI"

        traffic_path = f"{source_segment} -> {target_segment}"
        protocol = ctx.get('protocol', 'HTTPS')

        allowed_protocols = FIREWALL_RULES.get(traffic_path, [])
        if protocol not in allowed_protocols:
            reason = f"Microsegmentation Violation: Protocol '{protocol}' blocked on path {traffic_path}"
            self.logger.log("FIREWALL_BLOCK", 100, {"user": user, "protocol": protocol, "path": traffic_path})
            return {"status": "BLOCKED (FIREWALL)", "reason": reason}


        # === PHASE 2: ADAPTIVE RISK ANALYSIS ===

        req_ip = ctx.get('ip_address', "10.0.0.5") # Default to internal IP
        req_loc = ctx.get('location', "Hospital_Local")
        req_time = ctx.get('timestamp', time.time())

        sensitivity = 10 if target_segment == "EHR_CORE" else 5

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
                self.logger.log("MFA_FAILURE", policy['score'], {"user": user, "reason": "Step-Up Auth Failed"})
                return {"status": "DENIED", "reason": "High Risk Access requires valid MFA"}
            self.logger.log("MFA_SUCCESS", policy['score'], {"user": user, "reason": "Step-Up Auth Passed"})
            print("   >>> MFA Validated. Proceeding.")
        
        new_session_id = self.session_mgr.create_session(user, user_obj['role'], ctx['device_id'], ctx)

        
        # === PHASE 3: DATA PROTECTION ===

        encrypted_data = self.vault.encrypt(ctx['data'])
        return {
            "status": "GRANTED", 
            "reason": f"Authorized (Risk Score: {policy['score']})",
            "session_id": new_session_id,
            "secure_payload": encrypted_data,
            "decrypted_view": ctx['data']
        }
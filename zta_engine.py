from config import NETWORK_SEGMENTS
from encryption import DataVault

class SecureAccessProxy:
    def __init__(self, identity_provider, device_manager, behavior_monitor):
        self.idp = identity_provider
        self.device_mgr = device_manager
        self.monitor = behavior_monitor
        self.vault = DataVault()
    
    def process_access_request(self, request_context):
        print(f"\n[ZTA ENGINE] Processing request from user: {request_context['user']}...")

        #Layer 1 : Identity
        is_auth, user_obj = self.idp.authenticate_user(request_context['user'], request_context['password'])
        if not is_auth:
            return {"status": "DENIED", "reason": f"Identity Failed: {user_obj}"}
        
        #Layer 2: MFA check
        if not self.idp.verify_mfa(request_context['user'], request_context['mfa']):
            return {"status": "DENIED", "reason": "MFA Failed: Invalid Token"}
        
        #Layer 3: Device Posture
        is_healthy, health_reason = self.device_mgr.assess_posture(request_context['device_id'])
        if not is_healthy:
            return {"status": "DENIED", "reason": f"Device Posture Failed: {health_reason}"}
        
        #Layer 4: Micro-Segmentation(RBAC)
        allowed_roles = NETWORK_SEGMENTS.get(request_context['target_segment'], [])
        if user_obj['role'] not in allowed_roles:
            return {"status": "DENIED", "reason": f"Segmentation Violation: Role '{user_obj['role']} cannot access '{request_context['target_segment']}"}
        
        #Layer 5: Behavior Anomaly
        is_anomaly, anomaly_reason = self.monitor.check_anomaly(request_context['user'])
        if is_anomaly:
            return {"status": "DENIED", "reason": f"Anomaly Detected: {anomaly_reason}"}
        
        #Access Granted
        encrypted_data = self.vault.encrpyt(request_context['data'])
        return {
            "status": "GRANTED", 
            "reason": "All checks passed.",
            "secure_payload": encrypted_data,
            "decrypted_view": request_context['data']
        }
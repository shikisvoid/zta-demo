import time
from identity import IdentityProvider
from device import DeviceManager
from threats import AdvancedPhishingGuard
from zta_engine import SecureAccessProxy

def run_scenarios():
    idp = IdentityProvider()
    dev_mgr = DeviceManager()
    phishing_guard = AdvancedPhishingGuard()
    
    zta = SecureAccessProxy(idp, dev_mgr)

    print("============================================================")
    print("   HEALTHCARE ZERO TRUST ARCHITECTURE - ADVANCED DEMO       ")
    print("============================================================")

    # --- SCENARIO 1: PHISHING (Perimeter Defense) ---
    print("\n\n--- [SCENARIO 1] Phishing Detection ---")
    email = "Urgent: Verify your password now or lose access"
    print(f"Incoming: '{email}'")
    verdict = phishing_guard.scan_email(email, sender="hacker@evil.com")
    print(f"Verdict: {verdict.upper()}")

    # --- SCENARIO 2: NORMAL LOGIN (Baseline) ---
    print("\n\n--- [SCENARIO 2] Dr. House Normal Access ---")
    req_normal = {
        "user": "dr_house", "password": "secure_password_123", "mfa": "mfa_taken_A1",
        "device_id": "ipad_pro_01", "target_segment": "EHR_CORE", "data": "Patient 101 Vitals",
        
        "ip_address": "10.2.1.45", "location": "Hospital_Local", "timestamp": time.time()
    }
    res = zta.process_access_request(req_normal)
    print(f"Outcome: {res['status']} | Reason: {res['reason']}")

    # --- SCENARIO 3: IMPOSSIBLE TRAVEL (Geo-Velocity) ---
    print("\n\n--- [SCENARIO 3] Impossible Travel Attack ---")
    
    req_travel = req_normal.copy()
    req_travel["location"] = "London"
    req_travel["ip_address"] = "82.15.22.11" 
    req_travel["timestamp"] = time.time() + 300 
    
    res = zta.process_access_request(req_travel)
    print(f"Outcome: {res['status']} | Reason: {res['reason']}")

    # --- SCENARIO 4: OFF-HOURS ACCESS (Time-of-Day) ---
    print("\n\n--- [SCENARIO 4] Suspicious Off-Hours Access ---")
    
    t = time.localtime()
    t_3am = time.mktime((t.tm_year, t.tm_mon, t.tm_mday, 3, 0, 0, 0, 0, -1))
    
    req_night = {
        "user": "nurse_joy", "password": "nurse_pass_456", "mfa": "mfa_taken_B2",
        "device_id": "ipad_pro_01", 
        "target_segment": "EHR_CORE", "data": "Discharge Summaries",
        
        "ip_address": "10.2.1.99", "location": "Hospital_Local", 
        "timestamp": t_3am
    }
    
    res = zta.process_access_request(req_night)
    print(f"Outcome: {res['status']} | Reason: {res['reason']}")

    # --- SCENARIO 5: LEGACY DEVICE (Hard Block) ---
    print("\n\n--- [SCENARIO 5] Legacy Device Access ---")
    req_legacy = {
        "user": "dr_house", "password": "secure_password_123", "mfa": "mfa_taken_A1",
        "device_id": "mri_console_x", # Windows XP Device
        "target_segment": "EHR_CORE", "data": "Scan Data",
        "ip_address": "10.2.1.45", "location": "Hospital_Local", "timestamp": time.time()
    }
    res = zta.process_access_request(req_legacy)
    print(f"Outcome: {res['status']} | Reason: {res['reason']}")

if __name__ == "__main__":
    run_scenarios()
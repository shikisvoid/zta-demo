import time
from identity import IdentityProvider
from device import DeviceManager
from threats import PhishingDetector, BehaviorMonitor
from zta_engine import SecureAccessProxy

def run_scenarios():
    idp = IdentityProvider()
    dev_mgr = DeviceManager()
    monitor = BehaviorMonitor()
    phishing_guard = PhishingDetector()

    zta = SecureAccessProxy(idp, dev_mgr, monitor)

    print("============================================================")
    print("   HEALTHCARE ZERO TRUST ARCHITECTURE - ATTACK SIMULATION   ")
    print("============================================================")

    print("\n\n--- [SCENARIO 1] Phishing Email Attack ---")
    emails = [
        "Urgent: Verify your password now or lose access",
        "Meeting notes for the radiology team"
    ]

    for email in emails:
        verdict = phishing_guard.scan_email(email)
        print(f"Incoming Email: '{email}'")
        print(f"-> Classifier Verdict: {verdict.upper()}")
        if verdict == "malicious":
            print("-> ACTION: Quarantined at Gateway.")
        else:
            print("-> ACTION: Delivered to Inbox.")

    print("\n\n--- [SCENARIO 2] Legacy Device Access (The 'Windows XP' Risk) ---")
    req = {
        "user": "nurse_joy", "password": "nurse_pass_456", "mfa": "mfa_token_B2",
        "device_id": "mri_console_x",
        "target_segment": "EHR_CORE", "data": "Patient Vitals"
    }

    result = zta.process_access_request(req)
    print(f"Outcome: {result['status']}")
    print(f"Reason: {result['reason']}")

    print("\n\n--- [SCENARIO 3] Lateral Movement (Engineer -> Patient Data) ---")
    req = {
        "user": "eng_bob", "password": "builder_pass_789", "mfa": "mfa_token_C3",
        "device_id": "eng_laptop_05", 
        "target_segment": "EHR_CORE",
        "data": "Patient Database"
    }

    result = zta.process_access_request(req)
    print(f"Outcome: {result['status']}")
    print(f"Reason: {result['reason']}")

    print("\n\n--- [SCENARIO 4] Authorized Access (Doctor -> EHR) ---")
    req = {
        "user": "dr_house", "password": "secure_password_123", "mfa": "mfa_token_A1",
        "device_id": "ipad_pro_01", 
        "target_segment": "EHR_CORE", 
        "data": "Patient ID: 999 - Diagnosis: Lupis"
    }

    print(f"Outcome: {result['status']}")
    if result['status'] == "GRANTED":
        print(f"Encrypted Traffic: {result['secure_payload']}")
        print(f"Doctor Sees: {result['decrypted_view']}")

    print("\n\n--- [SCENARIO 5] Insider Threat (Rapid Data Export) ---")
    print("Simulating rapid requests...")
    for i in range(5):
        print(f"Request #{i+1}...", end=" ")
        result = zta.process_access_request(req)
        print(result['status'])
        if result['status'] == 'DENIED':
            print(f"Final Block Reason: {result['reason']}")
            break
    
if __name__ == "__main__":
    run_scenarios()
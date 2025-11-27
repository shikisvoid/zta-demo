import time
import json
from identity import IdentityProvider
from device import DeviceManager
from threats import AdvancedPhishingGuard
from zta_engine import SecureAccessProxy

def print_network_architecture():
    print(r"""
================================================================================
                ZERO TRUST ARCHITECTURE: LOGICAL TRAFFIC FLOW
================================================================================

      [ UNTRUSTED ZONE: USERS & DEVICES ]
      (Doctor, Nurse, IoMT Device, Hacker)
                   |
                   |  1. Access Request (Identity + Device + Context)
                   v
    +------------------------------------------------------------------+
    |                 SECURE ACCESS PROXY (THE GATEWAY)                |
    |                                                                  |
    |   +--- PHASE 1: HARD SECURITY CHECKS ------------------------+   |
    |   |                                                          |   |
    |   |  [ CHECK 1 ] Identity Provider (IdP)                     |   |
    |   |     |--> Invalid Creds? ----------------------------+    |   |
    |   |     v                                               |    |   |
    |   |  [ CHECK 2 ] Device Posture (Health)                |    |   |
    |   |     |--> Malware/EOL OS? ---------------------------+    |   |
    |   |     v                                               |    |   |
    |   |  [ CHECK 3 ] RBAC (Role Check)                      |    |   |
    |   |     |--> Wrong Role? -------------------------------+    |   |
    |   |     v                                               |    |   |
    |   |  [ CHECK 4 ] Microsegmentation Firewall             |    |   |
    |   |     |--> Invalid Protocol (e.g. SSH)? --------------+    |   |
    |   +-----------------------------------------------------+    |   |
    |             | (All Hard Checks Passed)                      |    |
    |             v                                               |    |
    |   +--- PHASE 2: INTELLIGENCE & ADAPTIVE RISK ------------+   |   |
    |   |                                                      |   |   |
    |   |  [ RISK ENGINE ] Context Analysis                    |   |   |
    |   |     (Time-of-Day, Impossible Travel, IP Rep)         |   |   |
    |   |     |                                                |   |   |
    |   |     +--> [ HIGH RISK ] --> Require MFA --> [ VERIFY ]    |   |
    |   |     |                                       | (Fail)     |   |
    |   |     +--> [ CRITICAL ] ----------------------+-------+    |   |
    |   |     |                                       |       |    |   |
    |   |     v (Low Risk / MFA Passed)               v       |    |   |
    |   |  [ DATA VAULT ] Encryption Engine        [ BLOCK ]  |    |   |
    |   +---------------------------------------------|--------+   |   |
    |             |                                   |            |   |
    +-------------|-----------------------------------|------------+   |
                  |                                   |                |
                  | (2. Secure Tunnel)                | (Log Event)    |
                  v                                   v                |
    +-----------------------------+           +------------------+     |
    |   MICRO-SEGMENTED NETWORK   |           |  OBSERVABILITY   |     |
    |                             |           |                  |     |
    |  [ EHR Core ]  [ IoMT VLAN ]|           | [ SIEM LOG FILE ]|<----+
    |  [ Finance  ]  [ WiFi      ]|           +------------------+
    +-----------------------------+

================================================================================
    """)
def generate_siem_dashboard():

    print_network_architecture()

    print("\n\n")
    print("="*100)
    print(f"{'SIEM DASHBOARD - INCIDENT REPORT':^100}")
    print("="*100)
    print(f"{'TIMESTAMP':<25} | {'EVENT TYPE':<18} | {'RISK':<5} | {'DETAILS'}")
    print("-" * 100)
    
    try:
        with open("siem_logs.json", "r") as f:
            for line in f:
                entry = json.loads(line)
                # Format the details dictionary into a string
                details_str = str(entry['details'])
                # Truncate if too long for display
                if len(details_str) > 50: 
                    details_str = details_str[:47] + "..."
                
                print(f"{entry['timestamp']:<25} | {entry['event_type']:<18} | {str(entry['risk_score']):<5} | {details_str}")
    except FileNotFoundError:
        print("No logs found. Run the simulation first.")
    print("="*100)
    print("\n")

def run_lateral_movement_demo(zta):
    print("\n" + "="*80)
    print("   [SCENARIO 10] LATERAL MOVEMENT: DATABASE EXFILTRATION ATTEMPT")
    print("="*80)

    # --- PHASE 1: THE COMPROMISE (Successful Entry) ---
    print("\n[PHASE 1] INITIAL BREACH (Phishing Success)")
    print(">> ATTACKER: Stolen credentials for 'dr_house' used to log in.")
    
    # FIX: Added 'data' field to prevent KeyError
    req_breach = {
        "user": "dr_house", 
        "password": "secure_password_123", 
        "mfa": "mfa_taken_A1",
        "device_id": "ipad_pro_01", 
        "target_segment": "EHR_CORE", 
        "ip_address": "10.2.1.45", 
        "location": "Hospital_Local", 
        "timestamp": time.time(),
        "protocol": "HTTPS",
        "data": "Initial Login Data"  # <--- THIS LINE WAS MISSING
    }
    
    res_breach = zta.process_access_request(req_breach)
    
    if res_breach['status'] == "GRANTED":
        print(f" [SUCCESS] Attacker authenticated! Session established.")
        print(f"   Context: Valid User (Doctor) | Valid Device (iPad) | Valid Path (HTTPS)")
    else:
        print(" Setup failed.")
        return

    # --- PHASE 2: THE PIVOT (Lateral Movement) ---
    print("\n[PHASE 2] THE LATERAL MOVE (Database Direct Access)")
    print(">> ATTACKER: Attempting to bypass the Web App and query the DB directly...")
    print(">> ACTION: Opening Socket to port 5432 (PostgreSQL) on EHR Server.")

    # Attacker tries to use the valid session to send SQL traffic
    req_lateral = req_breach.copy()
    req_lateral["protocol"] = "POSTGRES_SQL" 
    req_lateral["data"] = "SELECT * FROM patients_table WHERE diagnosis = 'HIV';"
    
    print(f"   Target Segment: EHR_CORE")
    print(f"   Protocol:       {req_lateral['protocol']}")
    
    # --- PHASE 3: ZTA ENFORCEMENT ---
    print("\n[PHASE 3] ZERO TRUST ENFORCEMENT")
    res_lateral = zta.process_access_request(req_lateral)
    
    print(f"   Outcome: {res_lateral['status']}") 
    print(f"   Reason:  {res_lateral['reason']}")
    
    if "FIREWALL" in res_lateral['status']:
        print("\n  [DEMO SUCCESSFUL] Microsegmentation Active!")
        print("   The firewall rule 'HOSPITAL_LOCAL -> EHR_CORE' only allows ['HTTPS', 'TLS_1.3'].")
        print("   The attempt to use 'POSTGRES_SQL' was blocked, despite the user being a valid Doctor.")
    print("="*80 + "\n")

def run_brute_force_demo(zta):
    print("\n" + "="*80)
    print("   [SCENARIO 11] IDENTITY PROTECTION: BRUTE FORCE & ACCOUNT LOCKOUT")
    print("="*80)

    target_user = "dr_house"
    print(f"\n[STEP 1] ATTACKER: Starting Brute Force Attack on '{target_user}'...")
    print("   (Policy: Account locks after 3 failed attempts)")

    password_list = ["wrong_pass_1", "123456", "admin", "secure_password_123"]

    for i, pwd in enumerate(password_list):
        attempt_num = i + 1
        print(f"\n   >> Attempt {attempt_num}: Trying password '{pwd}'")
        
        req = {
            "user": target_user, 
            "password": pwd,
            "device_id": "unknown_laptop", 
            "target_segment": "EHR_CORE", 
            "ip_address": "192.168.1.100", 
            "location": "Unknown", 
            "timestamp": time.time(),
            "protocol": "HTTPS",
            "data": "Login Packet"
        }

        result = zta.process_access_request(req)
        
        print(f"   Outcome: {result['status']}")
        print(f"   Reason:  {result['reason']}")

        if "Locked" in result['reason']:
            print(f"\n[!] LOCKOUT CONFIRMED on Attempt {attempt_num}")
            if pwd == "secure_password_123":
                print("    (Note: This was the CORRECT password, but it was blocked by the lock!)")
    print("\n" + "="*80 + "\n")

def run_device_posture_demo(zta):
    print("\n" + "="*80)
    print("   [SCENARIO 12] ROBUST DEVICE POSTURE: COMPLIANCE CHECKS")
    print("="*80)

    print("\n[TEST] Access Attempt from 'Nurse Station Laptop'")
    print("   Attributes: Managed=True, Antivirus=True, OS=Win11")
    print("   Flaw:       Disk Encryption is DISABLED")

    req = {
        "user": "nurse_joy", 
        "password": "nurse_pass_456", 
        "mfa": "mfa_taken_B2",
        "device_id": "nurse_laptop_compliance_fail", 
        "target_segment": "EHR_CORE", 
        "ip_address": "10.2.1.99", 
        "location": "Hospital_Local", 
        "timestamp": time.time(),
        "protocol": "HTTPS",
        "data": "Patient Vitals"
    }

    result = zta.process_access_request(req)

    print(f"   Outcome: {result['status']}")
    print(f"   Reason:  {result['reason']}")

    if "Encryption" in result['reason']:
        print("\n[!] SUCCESS: The system correctly blocked a managed device because it lacked encryption.")
    
    print("="*80 + "\n")

def run_scenarios():
    idp = IdentityProvider()
    dev_mgr = DeviceManager()
    phishing_guard = AdvancedPhishingGuard()
    zta = SecureAccessProxy(idp, dev_mgr)

    print("============================================================")
    print("   HEALTHCARE ZERO TRUST ARCHITECTURE - COMPREHENSIVE DEMO  ")
    print("============================================================")

    # --- PART 1: THREAT DETECTION ---
    print("\n\n=== PART 1: THREAT INTELLIGENCE ===")
    
    # [SCENARIO 1] Phishing
    print("\n--- [SCENARIO 1A] Standard Phishing Attack ---")
    email_1 = "Urgent: Verify your password now or lose access"
    sender_1 = "hacker@evil.com"
    print(f"Incoming: '{email_1}' FROM '{sender_1}'")

    report_1 = phishing_guard.scan_email(email_1, sender=sender_1)
    print(f"Verdict: {report_1['verdict']} (Conf: {report_1['confidence']})")
    print(f"Flags:   {report_1['flags']}")

    print("\n--- [SCENARIO 1B] Typosquatting Attack (Advanced) ---")
    email_2 = "Please review the attached patient file."
    # Looks like hospital.org, but uses '1' instead of 'l'
    sender_2 = "admin@hospita1.org" 
    print(f"Incoming: '{email_2}' FROM '{sender_2}'")

    report_2 = phishing_guard.scan_email(email_2, sender=sender_2)
    print(f"Verdict: {report_2['verdict']} (Conf: {report_2['confidence']})")
    print(f"Flags:   {report_2['flags']}")

    # --- PART 2: ACCESS CONTROL & ADAPTIVE RISK ---
    print("\n\n=== PART 2: ACCESS CONTROL & RISK ENGINE ===")

    # [SCENARIO 2] Normal Login
    print("\n--- [SCENARIO 2] Valid Doctor Access (Baseline) ---")
    req_valid = {
        "user": "dr_house", "password": "secure_password_123", "mfa": "mfa_taken_A1",
        "device_id": "ipad_pro_01", "target_segment": "EHR_CORE", "data": "Patient Vitals",
        "ip_address": "10.2.1.45", "location": "Hospital_Local", "timestamp": time.time(),
        "protocol": "HTTPS"
    }
    res_login = zta.process_access_request(req_valid)
    print(f"Outcome: {res_login['status']} | Reason: {res_login['reason']}")

    active_session_id = res_login.get('session_id')
    if active_session_id:
        print(f"   [+] Session Token Generated: {active_session_id}")
    else:
        print("   [-] No Session Token Generated (Check zta_engine.py)")

    # [SCENARIO 3] Impossible Travel
    print("\n--- [SCENARIO 3] Impossible Travel (London) ---")
    req_travel = req_valid.copy()
    req_travel["location"] = "London"
    req_travel["timestamp"] = time.time() + 300 
    res = zta.process_access_request(req_travel)
    print(f"Outcome: {res['status']} | Reason: {res['reason']}")

    # [SCENARIO 4] Off-Hours Access
    print("\n--- [SCENARIO 4] Off-Hours Access (3 AM) ---")
    t_3am = time.mktime(time.localtime()) - (time.localtime().tm_hour * 3600) + (3 * 3600)
    req_night = {
        "user": "nurse_joy", "password": "nurse_pass_456", "mfa": "mfa_taken_B2",
        "device_id": "ipad_pro_01", "target_segment": "EHR_CORE", "data": "Discharge Summaries",
        "ip_address": "10.2.1.99", "location": "Hospital_Local", "timestamp": t_3am,
        "protocol": "HTTPS"
    }
    res = zta.process_access_request(req_night)
    print(f"Outcome: {res['status']} | Reason: {res['reason']}")

    # [SCENARIO 5] Legacy Device
    print("\n--- [SCENARIO 5] Legacy Device Access (Windows XP) ---")
    req_legacy = req_valid.copy()
    req_legacy["device_id"] = "mri_console_x"
    res = zta.process_access_request(req_legacy)
    print(f"Outcome: {res['status']} | Reason: {res['reason']}")

    # --- PART 3: MICROSEGMENTATION (New Features) ---
    print("\n\n=== PART 3: MICROSEGMENTATION & LATERAL MOVEMENT ===")

    # [SCENARIO 6] Lateral Movement (SSH Attack)
    print("\n--- [SCENARIO 6] Lateral Movement Attempt (SSH) ---")
    # Hacker uses Dr. House's stolen credentials to try SSH into the DB.
    # Identity is Valid. Device is Valid. Protocol is INVALID.
    req_attack = req_valid.copy()
    req_attack["protocol"] = "SSH" 
    print(f"Action: Doctor attempting SSH connection...")
    res = zta.process_access_request(req_attack)
    print(f"Outcome: {res['status']} | Reason: {res['reason']}")

    # [SCENARIO 7] Valid IoMT Traffic (HL7)
    print("\n--- [SCENARIO 7] Valid IoMT Device Traffic (HL7) ---")
    # IoMT Engineer sending medical data via HL7 protocol
    req_iomt = {
        "user": "eng_bob", "password": "builder_pass_789", "mfa": "mfa_taken_C3",
        "device_id": "eng_laptop_05", "target_segment": "EHR_CORE", "data": "MRI_PACKET",
        "ip_address": "10.5.5.5", "location": "Hospital_Local", "timestamp": time.time(),
        "protocol": "HL7" 
    }
    res = zta.process_access_request(req_iomt)
    print(f"Outcome: {res['status']} | Reason: {res['reason']}")

    # [SCENARIO 8] IoMT Device Misuse (Web Browsing)
    print("\n--- [SCENARIO 8] IoMT Device Misuse (Web Browsing) ---")
    # An MRI machine trying to open a Web Browser (HTTPS) to the internet/EHR.
    # Blocked because MRI machines are only allowed to use HL7/DICOM.
    req_iomt_bad = req_iomt.copy()
    req_iomt_bad["protocol"] = "HTTPS"
    res = zta.process_access_request(req_iomt_bad)
    print(f"Outcome: {res['status']} | Reason: {res['reason']}")

    print("\n\n=== PART 4: CONTINUOUS AUTHENTICATION & SESSION SECURITY ===")

    if active_session_id:
        # [SCENARIO 7A] Valid Session Activity
        print("\n--- [SCENARIO 7A] Valid Session Usage (1 min later) ---")
        req_continue = {
            "user": "dr_house", "session_id": active_session_id, # USING TOKEN
            "ip_address": "10.2.1.45", "location": "Hospital_Local", 
            "timestamp": time.time() + 60, # 1 min later
            "data": "More Patient Data"
        }
        res = zta.process_access_request(req_continue)
        print(f"Outcome: {res['status']} | Reason: {res['reason']}")

        # [SCENARIO 7B] Session Hijacking (Token Theft)
        print("\n--- [SCENARIO 7B] Session Hijacking Attempt (IP Change) ---")
        # Hacker steals the session ID but uses it from a different IP
        req_hijack = {
            "user": "dr_house", "session_id": active_session_id,
            "ip_address": "192.168.1.100", # ATTACKER IP
            "location": "Hospital_Local",
            "timestamp": time.time() + 120, # 2 mins later
            "data": "Exfiltrate All Data"
        }
        res = zta.process_access_request(req_hijack)
        print(f"Outcome: {res['status']} | Reason: {res['reason']}")
        
        # [SCENARIO 7C] Idle Timeout
        print("\n--- [SCENARIO 7C] Idle Timeout (Walked Away) ---")
        # Simulating a new login to get a fresh token for this test
        print("(Simulating fresh login for timeout test...)")
        fresh_login = zta.process_access_request(req_valid)
        timeout_session = fresh_login.get('session_id')
        
        req_timeout = {
            "user": "dr_house", "session_id": timeout_session,
            "ip_address": "10.2.1.45", "location": "Hospital_Local",
            "timestamp": time.time() + 600, # 10 minutes later (Limit is 5)
            "data": "Patient Data"
        }
        res = zta.process_access_request(req_timeout)
        print(f"Outcome: {res['status']} | Reason: {res['reason']}")

        print("\n--- [SCENARIO 9] Data Tampering Attack (Man-in-the-Middle) ---")
        
        # 1. Create a valid request
        print("1. Generating legitimate medical record...")
        req_valid = {
            "user": "dr_house", "password": "secure_password_123", "mfa": "mfa_taken_A1",
            "device_id": "ipad_pro_01", "target_segment": "EHR_CORE", "data": "Prescription: 10mg Morphine",
            "ip_address": "10.2.1.45", "location": "Hospital_Local", "timestamp": time.time(),
            "protocol": "HTTPS"
        }
        result = zta.process_access_request(req_valid)
        original_packet = result['secure_payload']
        print(f"   [Original Hash] {original_packet['integrity_hash']}")

        # 2. Simulate Attack (Tampering with the Ciphertext)
        print("\n2. ATTACKER: Intercepting and modifying packet in transit...")
        tampered_packet = original_packet.copy()
        # Attacker tries to change the ciphertext slightly (simulated corruption)
        tampered_packet['ciphertext'] = tampered_packet['ciphertext'][:-4] + "AAAA"
        
        # 3. Verify
        print("3. RECEIVER: Attempting to decrypt and verify integrity...")
        verification_result = zta.vault.decrypt_and_verify(tampered_packet)
        
        # Using red color for alert
        if "COMPROMISED" in verification_result or "ERROR" in verification_result:
            print(f"\033[91m{verification_result}\033[0m")
        else:
            print(f"Decryption Successful: {verification_result}")

    run_lateral_movement_demo(zta)
    run_brute_force_demo(zta)
    run_device_posture_demo(zta)
    generate_siem_dashboard()

if __name__ == "__main__":
    run_scenarios()
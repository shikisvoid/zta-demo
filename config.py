NETWORK_SEGMENTS = {
    "EHR_CORE": ["Doctor", "Nurse"],
    "IOMT_VLAN": ["IoMT Engineer"],
    "FINANCE_SUBNET": ["Admin", "Finance"],
    "PUBLIC_WIFI": ["Guest", "Patient"]
}

FIREWALL_RULES = {
    "HOSPITAL_LOCAL -> EHR_CORE": ["HTTPS", "TLS_1.3"],
    "PUBLIC_WIFI -> EHR_CORE": ["HTTPS", "TLS_1.3"],
    "IOMT_VLAN -> EHR_CORE": ["HL7", "MQTT", "DICOM"],
    "FINANCE_SUBNET -> FINANCE_SUBNET": ["HTTPS", "SSH", "RDP"],

}

USERS_DB = {
    "dr_house": {
        "password": "secure_password_123",
        "role": "Doctor",
        "mfa_secret": "mfa_taken_A1"
    },
    "nurse_joy": {
        "password": "nurse_pass_456",
        "role": "Nurse",
        "mfa_secret": "mfa_taken_B2"
    },
    "eng_bob": {
        "password": "builder_pass_789",
        "role": "IoMT Engineer",
        "mfa_secret": "mfa_taken_C3"
    },
    "hacker_steve": {
        "password": "password123",
        "role": "External",
        "mfa_secret": None
   }
}

DEVICES_DB = {
    "ipad_pro_01": {
        "name": "Dr. House's iPad",
        "os": "iPadOS 17.5",
        "is_managed": True,
        "antivirus": True,
        "eol": False,
        "disk_encryption": True,
        "firewall": True
    },
    "mri_console_x": {
        "name": "MRI Machine Console",
        "os": "Windows XP SP3",
        "is_managed": True,
        "antivirus": False,
        "eol": True,
        "disk_encryption": False,
        "firewall": False
    },
    "eng_laptop_05": {
        "name": "Engineering ThinkPad",
        "os": "Windows 11",
        "is_managed": True,
        "antivirus": True,
        "eol": False,
        "disk_encryption": False,
        "firewall": False
    },
    "unknown_laptop": {
        "name": "Unknown Device",
        "os": "Kali Linux",
        "is_managed": False,
        "antivirus": False,
        "eol": False,
        "disk_encryption": True,
        "firewall": True
    },
    "nurse_laptop_compliance_fail": {
        "name": "Nurse Station Laptop",
        "os": "Windows 11",
        "is_managed": True,   
        "antivirus": True,    
        "eol": False,         
        "disk_encryption": False, 
        "firewall": True,      
    }
}
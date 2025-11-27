from config import DEVICES_DB

class DeviceManager:
    def assess_posture(self, device_id):
        device = DEVICES_DB.get(device_id)

        if not device:
            return False, "Unknown Device: Device not registered in inventory."
        
        if not device.get("is_managed"):
            return False, "Non-Compliant: Device is not managed by IT"
        
        if device["eol"]:
            return False, f"CRITICAL_RISK: Device OS '{device['os']}' is end-of-life."
        
        if not device.get("antivirus"):
            return False, "HIGH_RISK: Antivirus/EDR agent is missing or disabled."
        
        if not device.get("disk_encryption", False):
             return False, "COMPLIANCE_FAIL: Full Disk Encryption (BitLocker/FileVault) is disabled."
        
        if not device.get("firewall", False):
            return False, "SECURITY_RISK: Host-based firewall is disabled."
        
        return True, "HEALTHY"
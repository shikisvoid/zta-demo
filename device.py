from config import DEVICES_DB

class DeviceManager:
    def assess_posture(self, device_id):
        device = DEVICES_DB.get(device_id)
        if not device:
            return False, "Unknown Device: Device not registered in inventory."
        
        if not device["is_managed"]:
            return False, "Non-Compliant: Device is not managed by IT."
        
        if device["eol"]:
            return False, f"CRITICAL_RISK: Device OS '{device['os']}' is end-of-life."
        
        if not device["antivirus"]:
            return False, "HIGH_RISK"
        
        return True, "HEALTHY"
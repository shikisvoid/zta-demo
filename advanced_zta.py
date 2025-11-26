import time
import json
import math
from dataclasses import dataclass

GEO_DB = {
    "New York": (40.7128, -74.0060),
    "London": (51.5074, -0.1278),
    "Tokyo": (35.6895, 139.6917),
    "Hospital_Local": (40.7306, -73.9352)
}

@dataclass
class AccessRequest:
    user: str
    role: str
    ip_address: str
    location: str
    device_id: str
    resource_sensitivity: int
    timestamp: float

class SIEMLogger:
    def log(self, event_type, risk_score, details):
        log_entry = {
            "timestamp": time.time(),
            "event_type": event_type,
            "risk_score": risk_score,
            "details": details
        }
        print(f" [SIEM LOG] >> {json.dumps(log_entry)}")

class AdaptiveRiskEngine:
    def __init__(self):
        self.user_history = {}
        self.logger = SIEMLogger()

    def _calculate_distance(self, loc1, loc2):
        if loc1 not in GEO_DB or loc2 not in GEO_DB:
            return 0
        lat1, lon1 = GEO_DB[loc1]
        lat2, lon2 = GEO_DB[loc2]

        return math.sqrt((lat2 - lat1) ** 2 + (lon2 - lon1) ** 2) * 111
    
    def calculate_risk(self, req: AccessRequest):
        risk_score = 0
        reasons = []

        risk_score += req.resource_sensitivity * 5
        if req.resource_sensitivity > 8:
            reasons.append(f"High-Value Target (+{req.resource_sensitivity * 5})")
        
        current_hour = time.localtime(req.timestamp).tm_hour
        if current_hour < 6 or current_hour > 20: #Hospital Shift
            risk_score += 30
            reasons.append("Off-Hours Access (+30)")
        
        if req.user in self.user_history:
            last_login = self.user_history[req.user]
            distance = self._calculate_distance(last_login['location'], req.location)
            time_diff = (req.timestamp - last_login['timestamp']) / 3600

            if time_diff > 0 and (distance / time_diff) > 900:
                risk_score += 100
                reasons.append(f"Impossible Travel: {distance: .0f}km in {time_diff:.2f}h (+100)")
            
        self.user_history[req.user] = {
            "location": req.location,
            "timestamp": req.timestamp
        }

        if not req.ip_address.startswith("10."):
            risk_score += 20
            reasons.append("External Network Access (+20)")
        
        return risk_score, reasons
    
    def enforce_policy(self, request: AccessRequest):
        print(f"\n[RISK ENGINE] Analyzing: {request.user} | Loc: {request.location} | Time: {time.ctime(request.timestamp)}")

        score, reasons = self.calculate_risk(request)
        self.logger.log("RISK_ASSESSMENT", score, {"user": request.user, "reasons": reasons})

        if score > 80:
            return {"decision": "BLOCK", "score": score, "msg": "Critical Risk Detected"}
        elif score > 40:
            return {"decision": "MFA_CHALLENGE", "score": score, "msg": "Suspicious Activity - Step-Up Auth Required"}
        else:
            return {"decision": "ALLOW", "score": score, "msg": "Access Granted"}
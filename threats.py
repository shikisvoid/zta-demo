import re
from difflib import SequenceMatcher
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

class AdvancedPhishingGuard:
    def __init__(self):
        self.trusted_domains = ["hospital.org", "med-center.com"]

        self.training_data = [
            ("Urgent: Verify your password immediately or lose access", "malicious"),
            ("IT Alert: Your account password has expired. Click to reset.", "malicious"),
            ("HR: Important update regarding your direct deposit", "malicious"),
            ("Final Notice: Unpaid invoice #9921 attached", "malicious"),
            ("You have won a $500 Amazon Gift Card! Claim now.", "malicious"),
            ("Security Alert: Suspicious login detected from Russia", "malicious"),
            ("CEO Request: I need you to make a wire transfer urgently", "malicious"),
            ("Confidential: View the attached salary adjustment document", "malicious"),
            ("Access denied. Re-enter your credentials to unlock.", "malicious"),
            ("Your mailbox is full. Upgrade storage quota now.", "malicious"),
            ("Click here to view the shared document via Dropbox", "malicious"),
            
            # Safe Clinical/Operational Emails
            ("Meeting notes for the radiology department sync", "safe"),
            ("Patient files attached for Dr. House's review", "safe"),
            ("Lunch menu for the hospital cafeteria", "safe"),
            ("Dr. Smith, please check the X-Ray for patient #402", "safe"),
            ("Updated shift schedule for the nursing staff", "safe"),
            ("Lab results for Jane Doe are ready in the portal", "safe"),
            ("Grand Rounds presentation slides attached", "safe"),
            ("Reminder: Staff meeting tomorrow at 10 AM", "safe"),
            ("Inventory report for ICU supplies", "safe"),
            ("IT Support: Ticket #4422 has been resolved", "safe") 
        ]
        
        texts, labels = zip(*self.training_data)

        self.model = make_pipeline(TfidfVectorizer(stop_words='english'), MultinomialNB())
        self.model.fit(texts, labels)

    def _check_typosquatting(self, sender_email):
        try:
            sender_domain = sender_email.split('@')[1].lower()
        except IndexError:
            return False, "Invalid Email Format"
        
        if sender_domain in self.trusted_domains:
            return False, "Trusted Domain"
        
        for trusted in self.trusted_domains:
            similarity = SequenceMatcher(None, sender_domain, trusted).ratio()
            # If it's 80% to 99% similar, it's likely a trick (Typosquatting)
            if 0.80 < similarity < 1.0:
                return True, f"Typosquatting Detected! ({sender_domain} ~= {trusted})"
        return False, "External Domain"
    
    def _check_heuristics(self, content):
        score = 0
        flags = []
        content_lower = content.lower()

        if "urgent" in content_lower or "immediate" in content_lower:
            score += 20
            flags.append("Urgency Language")
        
        if any(w in content_lower for w in ["invoice", "wire transfer", "gift card"]):
            score += 30
            flags.append("Financial Trigger")

        if any(w in content_lower for w in ["password", "credential", "login", "verify"]):
            score += 40
            flags.append("Credential Harvesting")

        return score, flags

    def scan_email(self, content, sender="external"):
        result = {
            "verdict": "SAFE",
            "confidence": 0,
            "flags": []
        }

        # 1. Typosquatting Check (High Confidence)
        is_spoof, spoof_msg = self._check_typosquatting(sender)
        if is_spoof:
            result["verdict"] = "MALICIOUS"
            result["confidence"] = 1.0
            result["flags"].append(spoof_msg)
            return result 

        # 2. Machine Learning Analysis
        ml_verdict = self.model.predict([content])[0]
        ml_prob = self.model.predict_proba([content]).max()

        # 3. Heuristic Analysis
        heuristic_score, heuristic_flags = self._check_heuristics(content)
        result["flags"].extend(heuristic_flags)

        # 4. Final Decision Logic
        if ml_verdict == "malicious" and ml_prob > 0.6:
            result["verdict"] = "MALICIOUS"
            result["confidence"] = round(ml_prob, 2)
        elif heuristic_score >= 50:
            result["verdict"] = "MALICIOUS"
            result["confidence"] = 0.85
            result["flags"].append("High Heuristic Risk")
        
        if "External Domain" in spoof_msg and "Credential Harvesting" in result["flags"]:
            result["verdict"] = "MALICIOUS"
            result["confidence"] = 0.95
            result["flags"].append("External Sender Requesting Creds")

        return result
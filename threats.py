import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

class AdvancedPhishingGuard:
    def __init__(self):
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

    def _check_heuristics(self, content):

        risk_score = 0
        content_lower = content.lower()

        if "urgent" in content_lower or "immediate" in content_lower:
            risk_score += 20
        
        if any(w in content_lower for w in ["invoice", "wire transfer", "gift card", "direct deposit"]):
            risk_score += 30

        if any(w in content_lower for w in ["password", "credential", "login", "verify account"]):
            risk_score += 40

        return risk_score

    def scan_email(self, content, sender="external"):

        ml_verdict = self.model.predict([content])[0]
        ml_confidence = self.model.predict_proba([content]).max()
        
        heuristic_score = self._check_heuristics(content)

        is_external = "hospital.org" not in sender
        if is_external:
            heuristic_score += 10

        if ml_verdict == "malicious" and ml_confidence > 0.6:
            return "malicious"
        
        # If ML says safe, but Heuristics scream danger (Score > 50), override it.
        # This catches "Zero Day" attacks the ML model hasn't seen before.
        if heuristic_score >= 50:
            return "malicious (heuristic override)"

        return "safe"

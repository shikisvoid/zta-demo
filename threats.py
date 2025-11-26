import time
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

class PhishingDetector:
    def __init__(self):
        # Sample training data: (text, label)
        data = [
            ("Urgent: Verify your password now", "malicious"),
            ("You have won a lottery, click here", "malicious"),
            ("Action Required: Patient invoice overdue", "malicious"),
            ("HR: Update your direct deposit info", "malicious"),
            ("Meeting notes for the radiology team", "safe"),
            ("Patient files attached for review", "safe"),
            ("Lunch menu for the cafeteria", "safe"),
            ("Dr. Smith, please check the X-Ray", "safe")
        ]

        texts, label = zip(*data)
        self.model = make_pipeline(CountVectorizer(), MultinomialNB())
        self.model.fit(texts, label)

    def scan_email(self, content):
        return self.model.predict([content])[0]
    
class BehaviorMonitor:
    def __init__(self):
        self.request_log = {}

    def check_anomaly(self, username):
        current_time = time.time()
        if username not in self.request_log:
            self.request_log[username] = []
        
        self.request_log[username] = [t for t in self.request_log[username] if current_time - t < 10]
        self.request_log[username].append(current_time)

        if len(self.request_log[username]) > 3:
            return True, "Too many requests in short time - possible brute-force or data exfiltration"
        return False, "Normal activity"
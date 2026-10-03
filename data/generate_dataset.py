"""
Generate a safe synthetic phishing/legitimate email dataset.

Only fictional/example domains and reserved documentation IPs are used.
"""

from pathlib import Path
import csv
import random

OUT = Path(__file__).parent / "phishing_email_dataset.csv"
random.seed(42)

legit_templates = [
    ("university@example.org", "University workshop reminder",
     "Hello Student, this is a reminder that the cybersecurity workshop is scheduled for Friday at 10:00. No action is required."),
    ("hr@example.org", "HR policy update",
     "Hello Team, the updated employee handbook is available through the normal company portal. Please review it during your next workday."),
    ("project@example.org", "Project meeting reminder",
     "Hi Team, our project meeting is tomorrow at 11:00. Please bring your progress notes and questions."),
    ("shop@example.com", "Shopping confirmation",
     "Thank you for your order. Your fictional order confirmation is available in your account on our normal website."),
    ("newsletter@example.net", "Monthly newsletter",
     "Here is this month's security awareness newsletter with tips for safer email and web browsing."),
    ("training@example.org", "Cybersecurity workshop reminder",
     "Hello, this is a normal training reminder. Please attend the scheduled session. No password or payment information is requested."),
]

phish_templates = [
    ("security-alert@account-check.invalid.test", "URGENT: Verify Your Account Immediately",
     "Urgent action is required. Verify your password and personal details immediately or your account may be suspended.",
     "http://198.51.100.10/verify-account"),
    ("billing@invoice-check.invalid.test", "Payment overdue - immediate action",
     "Your outstanding invoice requires immediate payment. Confirm your account information now.",
     "http://203.0.113.10/pay-invoice"),
    ("rewards@prize-center.invalid.test", "You have won a reward",
     "Congratulations. You have won a reward. Confirm your personal information to claim it.",
     "http://198.51.100.20/claim-prize"),
    ("delivery@parcel-alert.invalid.test", "Delivery verification required",
     "Your delivery is waiting. Verify your details urgently to avoid cancellation.",
     "http://203.0.113.20/verify-delivery"),
    ("executive@request.invalid.test", "Urgent confidential request",
     "I need you to process this request immediately. Send the requested account details as soon as possible.",
     "http://198.51.100.30/request"),
]

rows = []
for i in range(300):
    sender, subject, body = random.choice(legit_templates)
    rows.append([f"L{i+1:04d}", sender, sender.split("@")[-1], subject, body, "", "", "LEGITIMATE"])

for i in range(300):
    sender, subject, body, url = random.choice(phish_templates)
    rows.append([f"P{i+1:04d}", sender, sender.split("@")[-1], subject, body, url, "", "PHISHING"])

random.shuffle(rows)
OUT.parent.mkdir(exist_ok=True)
with OUT.open("w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["email_id","sender","sender_domain","subject","body","urls","attachment_name","label"])
    writer.writerows(rows)

print(f"Created {len(rows)} records: {OUT}")

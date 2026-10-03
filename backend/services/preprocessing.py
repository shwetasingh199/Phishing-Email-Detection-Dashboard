import re
from .url_analyzer import extract_urls

def preprocess_email(sender: str, subject: str, body: str, attachment_name: str = "") -> dict:
    sender = (sender or "").strip()
    subject = (subject or "").strip()
    body = (body or "").strip()
    attachment_name = (attachment_name or "").strip()

    combined = f"{subject}\n{body}"
    urls = extract_urls(combined)

    return {
        "sender": sender,
        "subject": subject,
        "body": body,
        "attachment_name": attachment_name,
        "urls": urls,
        "sender_domain": sender.rsplit("@", 1)[-1].lower() if "@" in sender else "",
        "clean_text": re.sub(r"\s+", " ", combined).strip()
    }

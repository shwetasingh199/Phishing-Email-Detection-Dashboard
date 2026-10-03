import re
from email.utils import parseaddr

def analyze_sender(sender: str, display_name: str = "") -> dict:
    findings = []
    score = 0
    name, address = parseaddr(sender or "")

    if not address or "@" not in address:
        return {
            "sender_risk_score": 30,
            "sender_findings": [{
                "type": "invalid_sender",
                "description": "Sender does not look like a valid email address.",
                "severity": "high"
            }]
        }

    local, domain = address.rsplit("@", 1)
    domain_parts = domain.split(".")

    if len(domain) > 40:
        score += 5
        findings.append({
            "type": "long_domain",
            "description": "Sender domain is unusually long.",
            "severity": "low"
        })

    if len(domain_parts) > 4:
        score += 10
        findings.append({
            "type": "many_subdomains",
            "description": "Sender domain contains many subdomain levels.",
            "severity": "medium"
        })

    if re.search(r"[^a-zA-Z0-9._+-]", domain):
        score += 10
        findings.append({
            "type": "unusual_domain_characters",
            "description": "Sender domain contains unusual characters.",
            "severity": "medium"
        })

    if re.search(r"\d{4,}", local):
        score += 5
        findings.append({
            "type": "unusual_local_part",
            "description": "Sender local part contains an unusual numeric pattern.",
            "severity": "low"
        })

    if display_name and "@" in sender:
        expected = display_name.lower().replace(" ", "")
        if expected and expected not in domain.lower():
            score += 10
            findings.append({
                "type": "display_name_domain_mismatch",
                "description": "Display name and sender domain may not correspond.",
                "severity": "medium"
            })

    return {
        "sender_risk_score": min(score, 100),
        "sender_findings": findings,
        "sender_domain": domain.lower()
    }

import re

PATTERNS = {
    "urgency": [
        r"\burgent\b", r"\bimmediately\b", r"\bact now\b",
        r"\bas soon as possible\b", r"\bwithin \d+ hours?\b"
    ],
    "fear": [
        r"\bsuspend(ed|ion)?\b", r"\bdeactivat(ed|ion)?\b",
        r"\bavoid cancellation\b", r"\bwill be blocked\b"
    ],
    "financial_pressure": [
        r"\bpayment\b", r"\binvoice\b", r"\boutstanding\b",
        r"\brefund\b", r"\btransfer\b"
    ],
    "credential_request": [
        r"\bpassword\b", r"\bpasscode\b", r"\bverify your account\b",
        r"\blogin\b", r"\blog in\b"
    ],
    "personal_information": [
        r"\bpersonal details\b", r"\bpersonal information\b",
        r"\bdate of birth\b", r"\bidentity\b"
    ],
    "reward": [
        r"\byou have won\b", r"\bprize\b", r"\breward\b",
        r"\bcongratulations\b"
    ],
}

def analyze_email_content(subject: str, body: str) -> dict:
    text = f"{subject}\n{body}"
    findings = []
    counts = {}

    for category, patterns in PATTERNS.items():
        count = sum(len(re.findall(p, text, flags=re.I)) for p in patterns)
        counts[category] = count
        if count:
            findings.append({
                "type": category,
                "description": f"{category.replace('_', ' ').title()} language detected.",
                "severity": "medium" if category in {"urgency", "fear"} else "high"
            })

    generic_greeting = bool(re.search(
        r"^\s*(dear customer|dear user|hello customer|dear sir|dear madam)\b",
        body, re.I
    ))
    if generic_greeting:
        findings.append({
            "type": "generic_greeting",
            "description": "A generic greeting was detected.",
            "severity": "low"
        })

    exclamation_count = text.count("!")
    uppercase_letters = sum(c.isupper() for c in text if c.isalpha())
    alpha_letters = sum(c.isalpha() for c in text)
    uppercase_ratio = uppercase_letters / alpha_letters if alpha_letters else 0.0

    if exclamation_count >= 3:
        findings.append({
            "type": "excessive_exclamation",
            "description": "Multiple exclamation marks may indicate pressure or unusual formatting.",
            "severity": "low"
        })

    return {
        "findings": findings,
        "counts": counts,
        "generic_greeting": generic_greeting,
        "exclamation_count": exclamation_count,
        "uppercase_ratio": round(uppercase_ratio, 3),
        "body_length": len(body),
        "subject_length": len(subject),
        "contains_password_request": counts["credential_request"] > 0,
        "contains_personal_info_request": counts["personal_information"] > 0,
    }

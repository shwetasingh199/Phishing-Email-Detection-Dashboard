import re
from email.utils import parseaddr
from typing import Any, Dict, List


def _domain_from_email(value: str) -> str:
    """
    Extract a lowercase domain from an email address.
    """

    if not value:
        return ""

    _, address = parseaddr(value)

    if "@" not in address:
        return ""

    return address.rsplit("@", 1)[1].lower().strip()


def analyze_headers(
    sender: str,
    reply_to: str = "",
    authentication_results: str = "",
) -> Dict[str, Any]:
    """
    Analyze common email authentication headers.

    This is a heuristic parser. It should not be considered a replacement
    for complete mail-server authentication verification.
    """

    reasons: List[str] = []
    indicators: List[str] = []

    risk_score = 0

    sender_domain = _domain_from_email(sender)
    reply_domain = _domain_from_email(reply_to)

    if sender_domain and reply_domain:
        if sender_domain != reply_domain:
            risk_score += 20

            reasons.append(
                "Reply-To domain differs from the sender domain."
            )

            indicators.append(
                f"reply_to_mismatch:{sender_domain}->{reply_domain}"
            )

    auth = authentication_results.lower()

    checks = {
        "spf": r"\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)",
        "dkim": r"\bdkim\s*=\s*(pass|fail|neutral|none|temperror|permerror)",
        "dmarc": r"\bdmarc\s*=\s*(pass|fail|bestguesspass|none|temperror|permerror)",
    }

    for mechanism, pattern in checks.items():

        match = re.search(pattern, auth)

        if not match:
            continue

        result = match.group(1)

        if result in {
            "fail",
            "softfail",
            "permerror",
        }:

            if mechanism == "spf":
                risk_score += 15

            elif mechanism == "dkim":
                risk_score += 15

            elif mechanism == "dmarc":
                risk_score += 20

            reasons.append(
                f"{mechanism.upper()} authentication result: {result}."
            )

            indicators.append(
                f"{mechanism}:{result}"
            )

        elif result == "pass":

            indicators.append(
                f"{mechanism}:pass"
            )

    return {
        "risk_score": min(risk_score, 50),
        "reasons": reasons,
        "indicators": indicators,
        "sender_domain": sender_domain,
        "reply_to_domain": reply_domain,
    }
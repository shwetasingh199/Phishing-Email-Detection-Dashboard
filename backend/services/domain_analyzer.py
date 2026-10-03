from typing import Any, Dict, List
from urllib.parse import urlparse


TRUSTED_EXAMPLE_DOMAINS = {
    "example.org",
    "example.com",
    "example.net",
}


DISPOSABLE_HINTS = {
    "mailinator.com",
    "guerrillamail.com",
    "10minutemail.com",
    "tempmail.com",
}


BRAND_WORDS = {
    "microsoft",
    "google",
    "apple",
    "paypal",
    "amazon",
    "bank",
    "office365",
}


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain name.
    """

    if not domain:
        return ""

    domain = domain.strip().lower()

    if "://" in domain:
        try:
            domain = urlparse(domain).hostname or domain
        except Exception:
            pass

    domain = domain.rstrip(".")

    return domain


def analyze_domain(domain: str) -> Dict[str, Any]:
    """
    Perform heuristic domain analysis.

    These checks are signals, not proof that a domain is malicious.
    """

    domain = normalize_domain(domain)

    reasons: List[str] = []
    indicators: List[str] = []

    risk_score = 0

    if not domain:
        return {
            "domain": "",
            "risk_score": 0,
            "reasons": [],
            "indicators": [],
        }

    if domain in TRUSTED_EXAMPLE_DOMAINS:

        indicators.append(
            "trusted_example_domain"
        )

    if domain.startswith("xn--") or ".xn--" in domain:

        risk_score += 20

        reasons.append(
            "Domain uses punycode, which can be associated with look-alike domains."
        )

        indicators.append(
            "punycode_domain"
        )

    if domain in DISPOSABLE_HINTS:

        risk_score += 25

        reasons.append(
            "Domain matches a known disposable-email-domain hint."
        )

        indicators.append(
            "disposable_email_domain"
        )

    domain_without_tld = domain.rsplit(".", 1)[0]

    matched_brands = []

    for brand in BRAND_WORDS:
        if brand in domain_without_tld:
            matched_brands.append(brand)

    if matched_brands:

        risk_score += 15

        reasons.append(
            "Domain contains a brand-related keyword: "
            + ", ".join(sorted(matched_brands))
            + "."
        )

        indicators.append(
            "brand_keyword_domain"
        )

    label_lengths = [
        len(label)
        for label in domain.split(".")
        if label
    ]

    if any(length >= 30 for length in label_lengths):

        risk_score += 10

        reasons.append(
            "Domain contains an unusually long label."
        )

        indicators.append(
            "long_domain_label"
        )

    hyphen_count = domain.count("-")

    if hyphen_count >= 3:

        risk_score += 10

        reasons.append(
            "Domain contains many hyphens."
        )

        indicators.append(
            "many_hyphens"
        )

    return {
        "domain": domain,
        "risk_score": min(risk_score, 50),
        "reasons": reasons,
        "indicators": indicators,
    }
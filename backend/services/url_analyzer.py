import ipaddress
import re
from urllib.parse import urlparse

SHORTENER_HINTS = {"bit.ly", "tinyurl.com", "t.co", "shorturl.at"}
SUSPICIOUS_WORDS = {
    "verify", "login", "password", "account", "invoice",
    "payment", "confirm", "suspend", "credential", "reset"
}

def analyze_url(url: str) -> dict:
    url = (url or "").strip()
    findings = []
    score = 0

    if not url:
        return {"url": url, "risk_score": 0, "findings": []}

    candidate = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "http://" + url
    parsed = urlparse(candidate)
    hostname = parsed.hostname or ""

    if parsed.scheme.lower() != "https":
        score += 10
        findings.append("URL does not use HTTPS.")

    try:
        ipaddress.ip_address(hostname)
        score += 25
        findings.append("Hostname is a raw IP address.")
    except ValueError:
        pass

    if hostname.lower() in SHORTENER_HINTS:
        score += 15
        findings.append("Hostname resembles a URL-shortening service.")

    parts = hostname.split(".")
    if len(parts) > 4:
        score += 10
        findings.append("Hostname has many subdomain levels.")

    if len(url) > 120:
        score += 5
        findings.append("URL is unusually long.")

    if any(word in (parsed.path + "?" + parsed.query).lower() for word in SUSPICIOUS_WORDS):
        score += 15
        findings.append("URL contains security-sensitive keywords.")

    if re.search(r"[@%]", url):
        score += 5
        findings.append("URL contains characters that deserve closer review.")

    return {
        "url": url,
        "risk_score": min(score, 100),
        "findings": findings,
        "scheme": parsed.scheme.lower(),
        "hostname": hostname,
        "path": parsed.path,
        "query": parsed.query,
        "url_length": len(url),
        "hostname_length": len(hostname),
        "subdomain_count": max(len(parts) - 2, 0),
        "has_ip": _is_ip(hostname),
        "https": parsed.scheme.lower() == "https",
    }

def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False

def extract_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s<>\"]+", text or "", flags=re.I)

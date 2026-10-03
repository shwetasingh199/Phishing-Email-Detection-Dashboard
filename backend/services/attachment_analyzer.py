from pathlib import PurePath

DANGEROUS = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".msi", ".dll"}

def analyze_attachment(filename: str) -> dict:
    filename = (filename or "").strip()
    if not filename:
        return {"risk_score": 0, "findings": [], "extension": ""}

    lower = filename.lower()
    suffixes = [s.lower() for s in PurePath(lower).suffixes]
    findings = []
    score = 0

    if suffixes and suffixes[-1] in DANGEROUS:
        score += 25
        findings.append("Executable/script-like attachment extension detected.")

    if len(suffixes) >= 2 and suffixes[-1] in DANGEROUS:
        score += 20
        findings.append("Double-extension pattern detected.")

    return {
        "risk_score": min(score, 100),
        "findings": findings,
        "extension": suffixes[-1] if suffixes else ""
    }

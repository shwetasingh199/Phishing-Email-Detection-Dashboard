from typing import Any, Dict

from ml.predict import predict_email


def predict_if_available(
    sender: str,
    subject: str,
    body: str,
) -> Dict[str, Any]:
    """
    Run the trained ML model if it is available.

    If the model is unavailable, return a safe fallback result.
    """

    try:
        result = predict_email(
            sender=sender,
            subject=subject,
            body=body,
        )

        if not isinstance(result, dict):
            return {
                "available": False,
                "phishing_probability": None,
                "label": None,
            }

        return {
            "available": bool(
                result.get("available", False)
            ),
            "phishing_probability": result.get(
                "phishing_probability"
            ),
            "label": result.get("label"),
        }

    except Exception as exc:

        return {
            "available": False,
            "phishing_probability": None,
            "label": None,
            "error": str(exc),
        }
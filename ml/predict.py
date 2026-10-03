from pathlib import Path
import joblib

MODEL = Path(__file__).resolve().parent.parent / "models" / "phishing_tfidf_logreg.joblib"

def predict_email(sender: str, subject: str, body: str) -> dict:
    if not MODEL.exists():
        return {"available": False, "message": "Train the model first."}

    model = joblib.load(MODEL)
    text = f"{sender} {subject} {body}"
    probability = float(model.predict_proba([text])[0][1])
    return {
        "available": True,
        "phishing_probability": round(probability, 4),
        "label": "PHISHING" if probability >= 0.5 else "LEGITIMATE"
    }

if __name__ == "__main__":
    print(predict_email(
        "security-alert@account-check.invalid.test",
        "URGENT: Verify your account",
        "Verify your password immediately."
    ))

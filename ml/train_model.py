from pathlib import Path
import json
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "phishing_email_dataset.csv"
MODEL_DIR = ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)

df = pd.read_csv(DATA)
df["text"] = (
    df["sender"].fillna("") + " " +
    df["subject"].fillna("") + " " +
    df["body"].fillna("")
)
y = (df["label"] == "PHISHING").astype(int)

X_train, X_test, y_train, y_test = train_test_split(
    df["text"], y, test_size=0.2, random_state=42, stratify=y
)

model = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1)),
    ("classifier", LogisticRegression(max_iter=1000))
])

model.fit(X_train, y_train)
pred = model.predict(X_test)

metrics = {
    "accuracy": round(accuracy_score(y_test, pred), 4),
    "precision": round(precision_score(y_test, pred, zero_division=0), 4),
    "recall": round(recall_score(y_test, pred, zero_division=0), 4),
    "f1": round(f1_score(y_test, pred, zero_division=0), 4),
    "confusion_matrix": confusion_matrix(y_test, pred).tolist()
}

joblib.dump(model, MODEL_DIR / "phishing_tfidf_logreg.joblib")
(MODEL_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

print(json.dumps(metrics, indent=2))
print("Saved:", MODEL_DIR / "phishing_tfidf_logreg.joblib")

# Phishing Email Detection & Awareness Dashboard

A defensive, educational cybersecurity project that analyzes synthetic/sample emails using:
- sender analysis
- content/keyword analysis
- static URL analysis
- attachment filename analysis
- explainable rule-based risk scoring
- SQLite analysis history
- optional TF-IDF + Logistic Regression ML
- browser dashboard
- phishing-awareness checklist

## Safety
This project never visits submitted URLs, never executes attachments, never collects credentials, and is intended for synthetic/sample emails.

## Quick start

### 1. Create a virtual environment
Windows:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Generate the synthetic dataset
```bash
python data/generate_dataset.py
```

### 4. Train the optional ML model
```bash
python ml/train_model.py
```

### 5. Start the API/dashboard
```bash
uvicorn backend.app:app --reload
```

Open http://127.0.0.1:8000

### 6. Run tests
```bash
pytest -q
```

## Safe demonstration

Sender:
`security-alert@account-check.invalid.test`

Subject:
`URGENT: Verify Your Account Immediately`

Body:
`Urgent. Verify your password and account details immediately to avoid suspension.`

URL:
`http://198.51.100.10/verify-account`

The application should identify several risk signals, but the score is only a project heuristic and not proof of maliciousness.

## Architecture

Browser -> FastAPI -> analysis services -> risk engine -> SQLite

Optional ML:
dataset -> TF-IDF -> Logistic Regression -> saved model -> API prediction

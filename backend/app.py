
from collections import defaultdict, deque
from pathlib import Path
import time

from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from fastapi.staticfiles import StaticFiles
from pydantic import (
    BaseModel,
    Field,
    field_validator,
)

from .auth import (
    create_token,
    decode_token,
    hash_password,
    verify_password,
)

from .db import (
    create_user,
    get_user,
    init_db,
    list_analyses,
    get_stats,
    save_analysis,
    save_audit,
    get_audit_logs,
)

from .services.attachment_analyzer import (
    analyze_attachment,
)

from .services.content_analyzer import (
    analyze_email_content,
)

from .services.domain_analyzer import (
    analyze_domain,
)

from .services.eml_parser import (
    parse_eml_bytes,
)

from .services.header_analyzer import (
    analyze_headers,
)

from .services.ml_service import (
    predict_if_available,
)

from .services.preprocessing import (
    preprocess_email,
)

from .services.risk_engine import (
    calculate_phishing_score,
)

from .services.sender_analyzer import (
    analyze_sender,
)

from .services.url_analyzer import (
    analyze_url,
)


# -------------------------------------------------------------------
# Application
# -------------------------------------------------------------------

app = FastAPI(
    title="Advanced Phishing Email Detection Platform",
    version="2.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=False,
    allow_methods=[
        "GET",
        "POST",
    ],
    allow_headers=["*"],
)


security = HTTPBearer(
    auto_error=False
)


# -------------------------------------------------------------------
# Rate limiting
# -------------------------------------------------------------------

RATE_WINDOW = 60
RATE_LIMIT = 30

_requests = defaultdict(
    deque
)


# -------------------------------------------------------------------
# Request models
# -------------------------------------------------------------------

class RegisterRequest(BaseModel):
    username: str = Field(
        ...,
        min_length=3,
        max_length=40,
        pattern=r"^[a-zA-Z0-9_.-]+$",
    )

    password: str = Field(
        ...,
        min_length=10,
        max_length=128,
    )


class LoginRequest(RegisterRequest):
    pass


class EmailRequest(BaseModel):
    sender: str = Field(
        ...,
        max_length=320,
    )

    subject: str = Field(
        "",
        max_length=500,
    )

    body: str = Field(
        "",
        max_length=20000,
    )

    attachment_name: str = Field(
        "",
        max_length=255,
    )

    display_name: str = Field(
        "",
        max_length=200,
    )

    reply_to: str = Field(
        "",
        max_length=320,
    )

    auth_results: str = Field(
        "",
        max_length=5000,
    )

    @field_validator(
        "sender",
        "subject",
        "body",
        "attachment_name",
        "display_name",
        "reply_to",
        "auth_results",
        mode="before",
    )
    @classmethod
    def strip_strings(cls, value):
        if isinstance(
            value,
            str,
        ):
            return value.strip()

        return value


# -------------------------------------------------------------------
# Authentication
# -------------------------------------------------------------------

def current_user(
    credentials: HTTPAuthorizationCredentials = Depends(
        security
    ),
):
    """
    Validate the Bearer JWT.
    """

    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
        )

    try:
        return decode_token(
            credentials.credentials
        )

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token.",
        )


def rate_limit(
    user: dict,
):
    """
    Basic per-user in-memory rate limiter.
    """

    key = user.get(
        "sub",
        "anonymous",
    )

    now = time.time()

    queue = _requests[key]

    while (
        queue
        and now - queue[0] > RATE_WINDOW
    ):
        queue.popleft()

    if len(queue) >= RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=(
                "Rate limit exceeded. "
                "Try again shortly."
            ),
        )

    queue.append(now)


# -------------------------------------------------------------------
# Database initialization
# -------------------------------------------------------------------

init_db()


# -------------------------------------------------------------------
# Health
# -------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "version": app.version,
    }


# -------------------------------------------------------------------
# Register
# -------------------------------------------------------------------

@app.post("/api/auth/register")
def register(
    request: RegisterRequest,
):
    if get_user(
        request.username
    ):
        raise HTTPException(
            status_code=409,
            detail="Username already exists.",
        )

    create_user(
        request.username,
        hash_password(
            request.password
        ),
    )

    save_audit(
        request.username,
        "REGISTER",
    )

    return {
        "message": "User created."
    }


# -------------------------------------------------------------------
# Login
# -------------------------------------------------------------------

@app.post("/api/auth/login")
def login(
    request: LoginRequest,
):
    user = get_user(
        request.username
    )

    if (
        not user
        or not verify_password(
            request.password,
            user["password_hash"],
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password.",
        )

    token = create_token(
        user["username"],
        user["role"],
    )

    save_audit(
        user["username"],
        "LOGIN",
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"],
    }


# -------------------------------------------------------------------
# Main analysis pipeline
# -------------------------------------------------------------------

def _analyze(
    payload: EmailRequest,
    username: str,
    extra_attachments=None,
):
    """
    Run the complete phishing analysis pipeline.
    """

    # ---------------------------------------------------------------
    # Validation
    # ---------------------------------------------------------------

    if not payload.sender.strip():
        raise HTTPException(
            status_code=400,
            detail="Sender is required.",
        )

    if (
        not payload.subject.strip()
        and not payload.body.strip()
    ):
        raise HTTPException(
            status_code=400,
            detail="Subject or body is required.",
        )

    # ---------------------------------------------------------------
    # Preprocessing
    # ---------------------------------------------------------------

    prepared = preprocess_email(
        payload.sender,
        payload.subject,
        payload.body,
        payload.attachment_name,
    )

    # ---------------------------------------------------------------
    # Sender analysis
    # ---------------------------------------------------------------

    sender = analyze_sender(
        payload.sender,
        payload.display_name,
    )

    # ---------------------------------------------------------------
    # Content analysis
    # ---------------------------------------------------------------

    content = analyze_email_content(
        payload.subject,
        payload.body,
    )

    # ---------------------------------------------------------------
    # URL analysis
    # ---------------------------------------------------------------

    urls = [
        analyze_url(url)
        for url in prepared["urls"]
    ]

    # ---------------------------------------------------------------
    # Attachment analysis
    # ---------------------------------------------------------------

    attachment = analyze_attachment(
        payload.attachment_name
    )

    # ---------------------------------------------------------------
    # Header analysis
    # ---------------------------------------------------------------

    headers = analyze_headers(
        payload.sender,
        payload.reply_to,
        payload.auth_results,
    )

    # ---------------------------------------------------------------
    # Domain analysis
    # ---------------------------------------------------------------

    domain = analyze_domain(
        prepared["sender_domain"]
    )

    # ---------------------------------------------------------------
    # ML analysis
    # ---------------------------------------------------------------

    ml = predict_if_available(
        payload.sender,
        payload.subject,
        payload.body,
    )

    ml_probability = (
        ml.get(
            "phishing_probability"
        )
        if ml.get("available")
        else None
    )

    # ---------------------------------------------------------------
    # Risk engine
    # ---------------------------------------------------------------

    risk = calculate_phishing_score(
        sender,
        content,
        urls,
        attachment,
        headers,
        domain,
        ml_probability,
    )

    # ---------------------------------------------------------------
    # Indicators
    # ---------------------------------------------------------------

    indicators = []

    # Sender indicators
    for item in sender.get(
        "sender_findings",
        [],
    ):
        indicators.append(
            {
                "type": item["type"],
                "description": item[
                    "description"
                ],
                "severity": item[
                    "severity"
                ],
            }
        )

    # Content indicators
    for item in content.get(
        "findings",
        [],
    ):
        indicators.append(item)

    # Header indicators
    for item in headers.get(
        "findings",
        [],
    ):
        indicators.append(item)

    # Domain indicators
    for item in domain.get(
        "findings",
        [],
    ):
        indicators.append(item)

    # Attachment indicators
    for item in attachment.get(
        "findings",
        [],
    ):
        indicators.append(
            {
                "type": "attachment",
                "description": item,
                "severity": "high",
            }
        )

    # URL indicators
    for url in urls:
        for finding in url.get(
            "findings",
            [],
        ):
            indicators.append(
                {
                    "type": "url",
                    "description": finding,
                    "severity": "medium",
                }
            )

    # ---------------------------------------------------------------
    # Final result
    # ---------------------------------------------------------------

    result = {
        "sender_domain": prepared[
            "sender_domain"
        ],
        "subject": payload.subject,

        "risk_score": risk[
            "risk_score"
        ],

        "rule_score": risk[
            "rule_score"
        ],

        "ml_probability": ml_probability,

        "ml_contribution": risk[
            "ml_contribution"
        ],

        "classification": risk[
            "classification"
        ],

        "reasons": risk[
            "reasons"
        ],

        "recommendations": risk[
            "recommendations"
        ],

        "indicators": indicators,

        "sender_analysis": sender,

        "content_analysis": content,

        "header_analysis": headers,

        "domain_analysis": domain,

        "url_analysis": urls,

        "attachment_analysis": attachment,

        "uploaded_attachments": (
            extra_attachments or []
        ),
    }

    # ---------------------------------------------------------------
    # Database
    # ---------------------------------------------------------------

    analysis_id = save_analysis(
        result,
        username,
    )

    result[
        "analysis_id"
    ] = analysis_id

    save_audit(
        username,
        "ANALYZE_EMAIL",
        str(analysis_id),
    )

    return result


# -------------------------------------------------------------------
# Normal email analysis
# -------------------------------------------------------------------

@app.post("/api/analyze")
def analyze_email(
    request: EmailRequest,
    user=Depends(current_user),
):
    rate_limit(user)

    return _analyze(
        request,
        user["sub"],
    )


# -------------------------------------------------------------------
# EML upload analysis
# -------------------------------------------------------------------

@app.post("/api/analyze/eml")
async def analyze_eml(
    file: UploadFile = File(...),
    user=Depends(current_user),
):
    rate_limit(user)

    # ---------------------------------------------------------------
    # Validate filename
    # ---------------------------------------------------------------

    if (
        not file.filename
        or not file.filename.lower().endswith(
            ".eml"
        )
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Only .eml files are accepted."
            ),
        )

    # ---------------------------------------------------------------
    # Read file
    # ---------------------------------------------------------------

    data = await file.read()

    # ---------------------------------------------------------------
    # Parse EML
    # ---------------------------------------------------------------

    try:
        parsed = parse_eml_bytes(
            data
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unable to parse EML file: {exc}"
            ),
        )

    # ---------------------------------------------------------------
    # Convert parsed EML into EmailRequest
    # ---------------------------------------------------------------

    payload = EmailRequest(
        sender=parsed.get(
            "sender",
            "",
        ),
        reply_to=parsed.get(
            "reply_to",
            "",
        ),
        display_name=parsed.get(
            "display_name",
            "",
        ),
        subject=parsed.get(
            "subject",
            "",
        ),
        body=parsed.get(
            "body",
            "",
        ),
        attachment_name=parsed.get(
            "attachment_name",
            "",
        ),
        auth_results=parsed.get(
            "auth_results",
            "",
        ),
    )

    # ---------------------------------------------------------------
    # Analyze
    # ---------------------------------------------------------------

    result = _analyze(
        payload,
        user["sub"],
        parsed.get(
            "attachments",
            [],
        ),
    )

    # ---------------------------------------------------------------
    # Additional EML metadata
    # ---------------------------------------------------------------

    result[
        "eml_filename"
    ] = file.filename

    result[
        "eml_metadata"
    ] = {
        "message_id": parsed.get(
            "message_id",
            "",
        ),
        "date": parsed.get(
            "date",
            "",
        ),
        "reply_to": parsed.get(
            "reply_to",
            "",
        ),
        "auth_results": parsed.get(
            "auth_results",
            "",
        ),
        "attachments": parsed.get(
            "attachments",
            [],
        ),
    }

    return result


# -------------------------------------------------------------------
# Analysis history
# -------------------------------------------------------------------

@app.get("/api/analyses")
def analyses(
    user=Depends(current_user),
):
    return list_analyses()


# -------------------------------------------------------------------
# Dashboard statistics
# -------------------------------------------------------------------

@app.get("/api/dashboard/stats")
def dashboard_stats(
    user=Depends(current_user),
):
    return get_stats()


# -------------------------------------------------------------------
# Audit log
# -------------------------------------------------------------------

@app.get("/api/audit")
def audit_logs(
    user=Depends(current_user),
):
    if user.get(
        "role"
    ) != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin role required.",
        )

    return get_audit_logs()


# -------------------------------------------------------------------
# Frontend
# -------------------------------------------------------------------

FRONTEND = (
    Path(__file__).resolve().parent.parent
    / "frontend"
)

app.mount(
    "/",
    StaticFiles(
        directory=FRONTEND,
        html=True,
    ),
    name="frontend",
)

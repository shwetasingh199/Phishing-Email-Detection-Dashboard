
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import jwt


ROOT = Path(__file__).resolve().parent.parent
SECRET_FILE = ROOT / ".jwt_secret"

ALGORITHM = "HS256"
TOKEN_MINUTES = 60


def _secret() -> str:
    """
    Get or create the JWT signing secret.

    Priority:
    1. Existing .jwt_secret file
    2. JWT_SECRET environment variable
    3. Generate a new random secret
    """

    if SECRET_FILE.exists():
        secret = SECRET_FILE.read_text(
            encoding="utf-8"
        ).strip()

        if secret:
            return secret

    environment_secret = os.getenv(
        "JWT_SECRET"
    )

    if environment_secret:
        return environment_secret

    secret = os.urandom(32).hex()

    SECRET_FILE.write_text(
        secret,
        encoding="utf-8",
    )

    return secret


def hash_password(password: str) -> str:
    """
    Hash a password using scrypt.
    """

    if not isinstance(password, str):
        raise TypeError(
            "Password must be a string."
        )

    if len(password) < 8:
        raise ValueError(
            "Password must contain at least 8 characters."
        )

    salt = os.urandom(16)

    n = 2**14
    r = 8
    p = 1

    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
    )

    return (
        f"scrypt${n}${r}${p}$"
        f"{salt.hex()}${digest.hex()}"
    )


def verify_password(
    password: str,
    encoded: str,
) -> bool:
    """
    Verify a password against a stored scrypt hash.
    """

    if not isinstance(password, str):
        return False

    if not isinstance(encoded, str):
        return False

    try:
        (
            algorithm,
            n,
            r,
            p,
            salt_hex,
            digest_hex,
        ) = encoded.split("$")

        if algorithm != "scrypt":
            return False

        salt = bytes.fromhex(salt_hex)
        expected_digest = bytes.fromhex(
            digest_hex
        )

        actual_digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
        )

        return hmac.compare_digest(
            actual_digest,
            expected_digest,
        )

    except (ValueError, TypeError):
        return False


def create_token(
    username: str,
    role: str,
) -> str:
    """
    Create a JWT access token.
    """

    now = datetime.now(timezone.utc)

    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now
        + timedelta(
            minutes=TOKEN_MINUTES
        ),
    }

    return jwt.encode(
        payload,
        _secret(),
        algorithm=ALGORITHM,
    )


def decode_token(
    token: str,
) -> Dict[str, Any]:
    """
    Decode and validate a JWT token.
    """

    return jwt.decode(
        token,
        _secret(),
        algorithms=[ALGORITHM],
    )

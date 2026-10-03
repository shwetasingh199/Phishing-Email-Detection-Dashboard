
"""
Safe .eml file parser for the Phishing Email Detection Platform.

This module:
- Parses RFC-compliant .eml files.
- Extracts sender, Reply-To, subject and body.
- Extracts Authentication-Results.
- Extracts attachment metadata.
- Calculates SHA-256 hashes for attachments.
- Enforces a 2 MB input limit.
- Never executes or opens attachments.
"""

from email import policy
from email.message import Message
from email.parser import BytesParser
import hashlib


# Maximum .eml file size accepted by the API.
MAX_BYTES = 2 * 1024 * 1024


def _decode_part(part: Message) -> str:
    """
    Safely decode a text email part.

    Returns an empty string if the part cannot be decoded.
    """

    payload = part.get_payload(decode=True)

    if payload is None:
        return ""

    charset = part.get_content_charset() or "utf-8"

    try:
        return payload.decode(
            charset,
            errors="replace",
        )
    except (LookupError, UnicodeDecodeError):
        return payload.decode(
            "utf-8",
            errors="replace",
        )


def _walk_message(msg: Message):
    """
    Extract plain-text body content and attachment metadata.
    """

    body_parts = []
    attachments = []

    for part in msg.walk():

        # Multipart containers do not contain the actual payload.
        if part.is_multipart():
            continue

        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()

        payload = part.get_payload(
            decode=True
        ) or b""

        # Treat files and explicit attachments as attachments.
        if filename or disposition == "attachment":

            attachment_name = (
                filename
                or "unnamed_attachment"
            )

            attachments.append(
                {
                    "filename": attachment_name,
                    "content_type": content_type,
                    "size": len(payload),
                    "sha256": hashlib.sha256(
                        payload
                    ).hexdigest(),
                }
            )

            continue

        # Extract only text/plain content for analysis.
        if content_type == "text/plain":

            text = _decode_part(part)

            if text.strip():
                body_parts.append(
                    text.strip()
                )

    body = "\n".join(body_parts).strip()

    return body, attachments


def parse_eml_bytes(data: bytes) -> dict:
    """
    Parse raw .eml bytes.

    Parameters
    ----------
    data:
        Raw bytes from an uploaded .eml file.

    Returns
    -------
    dict
        Parsed email information.

    Raises
    ------
    ValueError
        If the file exceeds the maximum allowed size.
    """

    if not isinstance(data, bytes):
        raise ValueError(
            "Invalid .eml file data."
        )

    if len(data) > MAX_BYTES:
        raise ValueError(
            ".eml file exceeds the 2 MB safety limit."
        )

    try:
        message = BytesParser(
            policy=policy.default
        ).parsebytes(data)
    except Exception as exc:
        raise ValueError(
            "Unable to parse the .eml file."
        ) from exc

    body, attachments = _walk_message(
        message
    )

    return {
        "sender": message.get(
            "From",
            ""
        ),
        "reply_to": message.get(
            "Reply-To",
            ""
        ),
        "display_name": "",
        "subject": message.get(
            "Subject",
            ""
        ),
        "body": body,
        "attachment_name": (
            attachments[0]["filename"]
            if attachments
            else ""
        ),
        "attachments": attachments,
        "auth_results": message.get(
            "Authentication-Results",
            ""
        ),
        "message_id": message.get(
            "Message-ID",
            ""
        ),
        "date": message.get(
            "Date",
            ""
        ),
    }
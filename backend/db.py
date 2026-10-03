
"""
SQLite database layer for the Phishing Email Detection Platform.

This module provides:
- Database initialization
- User management
- Email analysis storage
- Indicator storage
- URL analysis storage
- Audit logging
- Dashboard statistics
- Compatibility with the original project database
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


# Database is stored in the project root.
DB_PATH = (
    Path(__file__).resolve().parent.parent
    / "app.db"
)


def get_connection():
    """
    Create and return a SQLite connection.
    """

    conn = sqlite3.connect(
        DB_PATH
    )

    conn.row_factory = sqlite3.Row

    # Enable foreign-key constraints.
    conn.execute(
        "PRAGMA foreign_keys=ON"
    )

    return conn


def init_db():
    """
    Create all required database tables.

    Also performs lightweight migrations for
    databases created by older project versions.
    """

    conn = get_connection()

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS analyses (
            analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            sender_domain TEXT,
            subject TEXT,
            risk_score INTEGER,
            ml_probability REAL,
            classification TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS indicators (
            indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            indicator_type TEXT,
            description TEXT,
            severity TEXT,
            FOREIGN KEY (
                analysis_id
            )
            REFERENCES analyses(analysis_id)
            ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS url_analyses (
            url_analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            url_safe_representation TEXT,
            risk_score INTEGER,
            findings TEXT,
            FOREIGN KEY (
                analysis_id
            )
            REFERENCES analyses(analysis_id)
            ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT NOT NULL,
            target TEXT,
            created_at TEXT NOT NULL
        );
        """
    )

    # ---------------------------------------------------------
    # Migrations for old databases
    # ---------------------------------------------------------

    analysis_columns = {
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(analyses)"
        ).fetchall()
    }

    if "username" not in analysis_columns:
        conn.execute(
            "ALTER TABLE analyses ADD COLUMN username TEXT"
        )

    if "ml_probability" not in analysis_columns:
        conn.execute(
            "ALTER TABLE analyses ADD COLUMN ml_probability REAL"
        )

    conn.commit()
    conn.close()


def get_user(username: str):
    """
    Retrieve a user by username.

    Returns:
        dict | None
    """

    conn = get_connection()

    row = conn.execute(
        """
        SELECT
            user_id,
            username,
            password_hash,
            role,
            created_at
        FROM users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()

    conn.close()

    if row is None:
        return None

    return dict(row)


def create_user(
    username: str,
    password_hash: str,
    role: str = "analyst",
):
    """
    Create a new user.

    The first registered account becomes admin.
    All subsequent accounts are analysts unless
    another role is explicitly supplied.
    """

    conn = get_connection()

    try:
        user_count = conn.execute(
            "SELECT COUNT(*) AS count FROM users"
        ).fetchone()["count"]

        if user_count == 0:
            role = "admin"

        created_at = (
            datetime.now(timezone.utc)
            .isoformat()
        )

        cursor = conn.execute(
            """
            INSERT INTO users (
                username,
                password_hash,
                role,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                username,
                password_hash,
                role,
                created_at,
            ),
        )

        conn.commit()

        return cursor.lastrowid

    except sqlite3.IntegrityError:
        conn.rollback()
        raise

    finally:
        conn.close()


def save_audit(
    username: str,
    action: str,
    target: str = "",
):
    """
    Store an audit-log event.
    """

    conn = get_connection()

    conn.execute(
        """
        INSERT INTO audit_logs (
            username,
            action,
            target,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            username,
            action,
            target,
            datetime.now(
                timezone.utc
            ).isoformat(),
        ),
    )

    conn.commit()
    conn.close()


def save_analysis(
    result: dict,
    username: str,
):
    """
    Save a complete email-analysis result.

    Returns:
        analysis_id
    """

    conn = get_connection()

    try:
        created_at = (
            datetime.now(timezone.utc)
            .isoformat()
        )

        cursor = conn.execute(
            """
            INSERT INTO analyses (
                username,
                sender_domain,
                subject,
                risk_score,
                ml_probability,
                classification,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                result.get(
                    "sender_domain",
                    "",
                ),
                result.get(
                    "subject",
                    "",
                ),
                result.get(
                    "risk_score",
                    0,
                ),
                result.get(
                    "ml_probability",
                ),
                result.get(
                    "classification",
                    "",
                ),
                created_at,
            ),
        )

        analysis_id = cursor.lastrowid

        # -----------------------------------------------------
        # Save indicators
        # -----------------------------------------------------

        for item in result.get(
            "indicators",
            [],
        ):

            if not isinstance(
                item,
                dict,
            ):
                continue

            conn.execute(
                """
                INSERT INTO indicators (
                    analysis_id,
                    indicator_type,
                    description,
                    severity
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    analysis_id,
                    item.get(
                        "type",
                        "unknown",
                    ),
                    str(
                        item.get(
                            "description",
                            "",
                        )
                    ),
                    item.get(
                        "severity",
                        "info",
                    ),
                ),
            )

        # -----------------------------------------------------
        # Save URL analysis
        # -----------------------------------------------------

        for item in result.get(
            "url_analysis",
            [],
        ):

            if not isinstance(
                item,
                dict,
            ):
                continue

            findings = item.get(
                "findings",
                [],
            )

            conn.execute(
                """
                INSERT INTO url_analyses (
                    analysis_id,
                    url_safe_representation,
                    risk_score,
                    findings
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    analysis_id,
                    str(
                        item.get(
                            "url",
                            "",
                        )
                    ),
                    item.get(
                        "risk_score",
                        0,
                    ),
                    json.dumps(
                        findings
                    ),
                ),
            )

        conn.commit()

        return analysis_id

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def list_analyses(
    limit: int = 100,
):
    """
    Return recent email analyses.
    """

    # Keep limit within a safe range.
    limit = max(
        1,
        min(
            int(limit),
            1000,
        ),
    )

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            analysis_id,
            username,
            sender_domain,
            subject,
            risk_score,
            ml_probability,
            classification,
            created_at
        FROM analyses
        ORDER BY analysis_id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    conn.close()

    return [
        dict(row)
        for row in rows
    ]


def get_stats():
    """
    Return dashboard statistics.
    """

    conn = get_connection()

    total = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM analyses
        """
    ).fetchone()["count"]

    average_risk = conn.execute(
        """
        SELECT
            COALESCE(
                AVG(risk_score),
                0
            ) AS average
        FROM analyses
        """
    ).fetchone()["average"]

    high_risk = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM analyses
        WHERE risk_score >= 71
        """
    ).fetchone()["count"]

    classification_rows = conn.execute(
        """
        SELECT
            classification,
            COUNT(*) AS count
        FROM analyses
        GROUP BY classification
        """
    ).fetchall()

    indicator_rows = conn.execute(
        """
        SELECT
            indicator_type,
            COUNT(*) AS count
        FROM indicators
        GROUP BY indicator_type
        ORDER BY count DESC
        LIMIT 10
        """
    ).fetchall()

    trend_rows = conn.execute(
        """
        SELECT
            substr(
                created_at,
                1,
                10
            ) AS day,
            COUNT(*) AS total,
            ROUND(
                AVG(risk_score),
                2
            ) AS avg_risk
        FROM analyses
        GROUP BY day
        ORDER BY day DESC
        LIMIT 14
        """
    ).fetchall()

    conn.close()

    return {
        "total": total,
        "average_risk": round(
            float(average_risk or 0),
            2,
        ),
        "high_risk": high_risk,
        "classifications": {
            row["classification"]: row["count"]
            for row in classification_rows
        },
        "top_indicators": [
            {
                "type": row["indicator_type"],
                "count": row["count"],
            }
            for row in indicator_rows
        ],
        "trend": [
            dict(row)
            for row in reversed(
                trend_rows
            )
        ],
    }


def get_audit_logs(
    limit: int = 100,
):
    """
    Return recent audit-log entries.
    """

    limit = max(
        1,
        min(
            int(limit),
            1000,
        ),
    )

    conn = get_connection()

    rows = conn.execute(
        """
        SELECT
            audit_id,
            username,
            action,
            target,
            created_at
        FROM audit_logs
        ORDER BY audit_id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    conn.close()

    return [
        dict(row)
        for row in rows
    ]


# Initialize the database when this module is imported.
init_db()

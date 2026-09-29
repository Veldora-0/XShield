import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "data" / "xshield.sqlite3"
_JSON_FIELDS = ("matched_rules", "reasons", "input_fields", "metadata")
_CURRENT_SCHEMA_VERSION = 4
_LEGACY_APPLICATION_SLUG = "legacy-local"


@contextmanager
def _connect(database_path: str | Path):
    connection = sqlite3.connect(str(database_path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database(database_path: str | Path = DEFAULT_DATABASE_PATH) -> None:
    """Create or upgrade the local SQLite schema without deleting records."""
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(path) as connection:
        _ensure_schema_migrations_table(connection)
        current_version = _get_schema_version(connection)
        if current_version < 1:
            _create_base_schema(connection)
            _set_schema_version(connection, 1)
            current_version = 1
        if current_version < 2:
            _migrate_to_multi_application_schema(connection)
            _set_schema_version(connection, 2)
            current_version = 2
        if current_version < 3:
            _migrate_to_api_key_schema(connection)
            _set_schema_version(connection, 3)
            current_version = 3
        if current_version < 4:
            _migrate_to_ingestion_event_schema(connection)
            _set_schema_version(connection, 4)
        _ensure_legacy_application(connection)


def _ensure_schema_migrations_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
        """
    )


def _get_schema_version(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations"
    ).fetchone()
    return int(row["version"])


def _set_schema_version(connection: sqlite3.Connection, version: int) -> None:
    connection.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (version, datetime.now(timezone.utc).isoformat(timespec="seconds")),
    )


def _create_base_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            input_text TEXT NOT NULL,
            rule_score REAL NOT NULL,
            ml_probability REAL NOT NULL,
            ml_prediction TEXT NOT NULL,
            hybrid_signal REAL NOT NULL,
            risk_score REAL NOT NULL,
            risk_level TEXT NOT NULL,
            action TEXT NOT NULL,
            detector_agreement TEXT NOT NULL,
            matched_rules TEXT NOT NULL,
            reasons TEXT NOT NULL
        )
        """
    )


def _table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    rows = connection.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()
    return {str(row["name"]) for row in rows}


def _migrate_to_multi_application_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_applications_status
        ON applications (status)
        """
    )

    columns = _table_columns(connection, "security_events")
    if "application_id" not in columns:
        connection.execute(
            """
            ALTER TABLE security_events
            ADD COLUMN application_id INTEGER REFERENCES applications(id)
            """
        )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_security_events_application_id
        ON security_events (application_id)
        """
    )

    legacy_id = _ensure_legacy_application(connection)
    connection.execute(
        """
        UPDATE security_events
        SET application_id = ?
        WHERE application_id IS NULL
        """,
        (legacy_id,),
    )


def _migrate_to_api_key_schema(connection: sqlite3.Connection) -> None:
    columns = _table_columns(connection, "applications")
    if "updated_at" not in columns:
        connection.execute(
            """
            ALTER TABLE applications
            ADD COLUMN updated_at TEXT
            """
        )
        connection.execute(
            """
            UPDATE applications
            SET updated_at = created_at
            WHERE updated_at IS NULL
            """
        )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER NOT NULL REFERENCES applications(id),
            key_hash TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            expires_at TEXT,
            last_used_at TEXT
        )
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_api_keys_application_id
        ON api_keys (application_id)
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_api_keys_status
        ON api_keys (status)
        """
    )


def _migrate_to_ingestion_event_schema(connection: sqlite3.Connection) -> None:
    columns = _table_columns(connection, "security_events")
    additions = {
        "event_type": "TEXT",
        "request_id": "TEXT",
        "http_method": "TEXT",
        "endpoint": "TEXT",
        "input_fields": "TEXT",
        "metadata": "TEXT",
        "retention_mode": "TEXT",
        "source": "TEXT",
    }
    for column, definition in additions.items():
        if column not in columns:
            connection.execute(
                f"ALTER TABLE security_events ADD COLUMN {column} {definition}"
            )


def _ensure_legacy_application(connection: sqlite3.Connection) -> int:
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    connection.execute(
        """
        INSERT OR IGNORE INTO applications
            (slug, name, description, status, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            _LEGACY_APPLICATION_SLUG,
            "Legacy Local Application",
            "Automatically created for existing local browser events.",
            "active",
            timestamp,
        ),
    )
    row = connection.execute(
        "SELECT id FROM applications WHERE slug = ?",
        (_LEGACY_APPLICATION_SLUG,),
    ).fetchone()
    if row is None:
        raise sqlite3.IntegrityError("legacy-local application could not be created")
    return int(row["id"])


def create_application(
    slug: str,
    name: str,
    description: str = "",
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> dict:
    """Create one registered application, rejecting duplicate slugs."""
    normalized_slug = str(slug).strip().casefold()
    application_name = str(name).strip()
    if not normalized_slug or not application_name:
        raise ValueError("Application slug and name are required.")
    if any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in normalized_slug
    ):
        raise ValueError(
            "Application slug may contain only lowercase letters, numbers, "
            "hyphens, and underscores."
        )
    with _connect(database_path) as connection:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        cursor = connection.execute(
            """
            INSERT INTO applications
                (slug, name, description, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                normalized_slug,
                application_name,
                str(description).strip(),
                "active",
                timestamp,
                timestamp,
            ),
        )
        row = connection.execute(
            "SELECT * FROM applications WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    return dict(row)


def get_application_by_slug(
    slug: str,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> dict | None:
    with _connect(database_path) as connection:
        row = connection.execute(
            "SELECT * FROM applications WHERE slug = ?",
            (str(slug),),
        ).fetchone()
    return dict(row) if row else None


def list_applications(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> list[dict]:
    with _connect(database_path) as connection:
        rows = connection.execute(
            "SELECT * FROM applications ORDER BY id"
        ).fetchall()
    return [dict(row) for row in rows]


def get_application_by_id(
    application_id: int,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> dict | None:
    with _connect(database_path) as connection:
        row = connection.execute(
            "SELECT * FROM applications WHERE id = ?",
            (int(application_id),),
        ).fetchone()
    return dict(row) if row else None


def set_application_status(
    application_id: int,
    status: str,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> dict:
    if status not in {"active", "revoked"}:
        raise ValueError("Application status must be active or revoked.")
    with _connect(database_path) as connection:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        cursor = connection.execute(
            """
            UPDATE applications
            SET status = ?, updated_at = ?
            WHERE id = ?
            """,
            (status, timestamp, int(application_id)),
        )
        if cursor.rowcount != 1:
            raise LookupError("Application not found.")
        row = connection.execute(
            "SELECT * FROM applications WHERE id = ?",
            (int(application_id),),
        ).fetchone()
    return dict(row)


def _serialize_list(values: list[Any]) -> str:
    return json.dumps(values, ensure_ascii=False)


def _deserialize_event(row: sqlite3.Row) -> dict:
    event = dict(row)
    for field in _JSON_FIELDS:
        if event.get(field) is not None:
            event[field] = json.loads(event[field])
    return event


def create_security_event(
    event: dict,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> dict:
    """Persist one completed detection event using a parameterized insert."""
    timestamp = event.get(
        "timestamp",
        datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    with _connect(database_path) as connection:
        application_id = event.get("application_id")
        if application_id is None:
            application_id = _ensure_legacy_application(connection)
        cursor = connection.execute(
            """
            INSERT INTO security_events (
                timestamp, input_text, rule_score, ml_probability,
                ml_prediction, hybrid_signal, risk_score, risk_level,
                action, detector_agreement, matched_rules, reasons,
                application_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                str(event["input_text"]),
                float(event["rule_score"]),
                float(event["ml_probability"]),
                str(event["ml_prediction"]),
                float(event["hybrid_signal"]),
                float(event["risk_score"]),
                str(event["risk_level"]),
                str(event["action"]),
                str(event["detector_agreement"]),
                _serialize_list(event.get("matched_rules", [])),
                _serialize_list(event.get("reasons", [])),
                int(application_id),
            ),
        )
        event_id = cursor.lastrowid
    return {"id": event_id, "timestamp": timestamp}


def create_ingested_event(
    event: dict,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> dict:
    """Persist one normalized, analyzed integration event."""
    analysis = event["analysis"]
    rule_result = analysis["rule_result"]
    ml_result = analysis["ml_result"]
    hybrid = analysis["hybrid"]
    risk_result = analysis["risk_result"]
    action_result = analysis["action_result"]
    timestamp = event["timestamp"]
    with _connect(database_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO security_events (
                timestamp, input_text, rule_score, ml_probability,
                ml_prediction, hybrid_signal, risk_score, risk_level,
                action, detector_agreement, matched_rules, reasons,
                application_id, event_type, request_id, http_method,
                endpoint, input_fields, metadata, retention_mode, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                event["input_text"],
                float(rule_result["score"]),
                float(ml_result["probability"]),
                str(ml_result["prediction"]),
                float(hybrid["hybrid_signal"]),
                float(risk_result["risk_score"]),
                str(risk_result["risk_level"]),
                str(action_result["action"]),
                str(hybrid["agreement"]),
                _serialize_list(rule_result.get("matched_rules", [])),
                _serialize_list(risk_result.get("reasons", [])),
                int(event["application_id"]),
                event["event_type"],
                event.get("request_id"),
                event.get("http_method"),
                event.get("endpoint"),
                json.dumps(event["input_fields"], ensure_ascii=False),
                json.dumps(event["metadata"], ensure_ascii=False),
                event["retention_mode"],
                "api",
            ),
        )
    return {"id": int(cursor.lastrowid), "timestamp": timestamp}


def get_recent_events(
    limit: int = 50,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> list[dict]:
    if limit < 1:
        raise ValueError("limit must be at least 1.")
    with _connect(database_path) as connection:
        rows = connection.execute(
            "SELECT * FROM security_events ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
    return [_deserialize_event(row) for row in rows]


def get_event_by_id(
    event_id: int,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> dict | None:
    with _connect(database_path) as connection:
        row = connection.execute(
            "SELECT * FROM security_events WHERE id = ?",
            (int(event_id),),
        ).fetchone()
    return _deserialize_event(row) if row else None


def count_events(database_path: str | Path = DEFAULT_DATABASE_PATH) -> int:
    with _connect(database_path) as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM security_events"
        ).fetchone()
    return int(row["total"])


def get_event_counts_by_risk(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> dict[str, int]:
    with _connect(database_path) as connection:
        rows = connection.execute(
            """
            SELECT risk_level, COUNT(*) AS total
            FROM security_events
            GROUP BY risk_level
            ORDER BY risk_level
            """
        ).fetchall()
    return {str(row["risk_level"]): int(row["total"]) for row in rows}


def get_dashboard_stats(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> dict:
    with _connect(database_path) as connection:
        total = connection.execute(
            "SELECT COUNT(*) AS total FROM security_events"
        ).fetchone()["total"]
        blocked = connection.execute(
            "SELECT COUNT(*) AS total FROM security_events "
            "WHERE action IN (?, ?)",
            ("block", "block_and_alert"),
        ).fetchone()["total"]
    risk_counts = get_event_counts_by_risk(database_path)
    return {
        "total_events": int(total),
        "blocked_events": int(blocked),
        "risk_counts": {
            level: int(risk_counts.get(level, 0))
            for level in ("Low", "Medium", "High", "Critical")
        },
    }


def get_filtered_events(
    *,
    limit: int = 50,
    risk_level: str | None = None,
    action: str | None = None,
    search: str | None = None,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> list[dict]:
    if limit < 1:
        raise ValueError("limit must be at least 1.")

    conditions = []
    parameters: list[object] = []
    if risk_level in {"Low", "Medium", "High", "Critical"}:
        conditions.append("risk_level = ?")
        parameters.append(risk_level)
    if action in {"allow", "flag", "block", "block_and_alert"}:
        conditions.append("action = ?")
        parameters.append(action)
    if search:
        conditions.append(
            "(input_text LIKE ? OR ml_prediction LIKE ? OR detector_agreement LIKE ?)"
        )
        term = f"%{search}%"
        parameters.extend((term, term, term))

    where_clause = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    query = (
        "SELECT * FROM security_events"
        f"{where_clause} ORDER BY id DESC LIMIT ?"
    )
    parameters.append(int(limit))
    with _connect(database_path) as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [_deserialize_event(row) for row in rows]

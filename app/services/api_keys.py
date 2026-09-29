"""Application API-key lifecycle and future integration authentication."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from app.database.db import (
    DEFAULT_DATABASE_PATH,
    _connect,
    get_application_by_id,
)


API_KEY_PREFIX = "xsh_"
_API_KEY_BYTES = 32


@dataclass(frozen=True)
class AuthenticationResult:
    authenticated: bool
    application: dict | None = None
    api_key_id: int | None = None
    reason: str | None = None


def _hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def generate_api_key() -> str:
    """Generate a 256-bit random API key with a recognizable prefix."""
    return f"{API_KEY_PREFIX}{secrets.token_urlsafe(_API_KEY_BYTES)}"


def create_api_key(
    application_id: int,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
    expires_at: str | None = None,
) -> dict:
    """Create a key and return its plaintext only in this result."""
    application = get_application_by_id(application_id, database_path)
    if application is None:
        raise LookupError("Application not found.")
    if application["status"] != "active":
        raise ValueError("Only active applications can receive API keys.")

    api_key = generate_api_key()
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _connect(database_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO api_keys
                (application_id, key_hash, status, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                int(application_id),
                _hash_api_key(api_key),
                "active",
                timestamp,
                expires_at,
            ),
        )
        return {
            "id": cursor.lastrowid,
            "application_id": int(application_id),
            "created_at": timestamp,
            "expires_at": expires_at,
            "api_key": api_key,
        }


def revoke_api_key(
    api_key_id: int,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> bool:
    with _connect(database_path) as connection:
        cursor = connection.execute(
            "UPDATE api_keys SET status = 'revoked' WHERE id = ?",
            (int(api_key_id),),
        )
    if cursor.rowcount != 1:
        raise LookupError("API key not found.")
    return True


def list_api_keys(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> list[dict]:
    """List metadata only; plaintext keys are never returned."""
    with _connect(database_path) as connection:
        rows = connection.execute(
            """
            SELECT id, application_id, status, created_at, expires_at, last_used_at
            FROM api_keys
            ORDER BY id
            """
        ).fetchall()
    return [dict(row) for row in rows]


def _header_value(headers: Mapping[str, str]) -> str | None:
    for name, value in headers.items():
        if name.casefold() == "x-api-key":
            return value.strip() or None
    return None


def authenticate_api_key(
    headers: Mapping[str, str],
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> AuthenticationResult:
    """Validate an X-API-Key header without exposing secret values."""
    api_key = _header_value(headers)
    if api_key is None:
        return AuthenticationResult(False, reason="missing_api_key")

    key_hash = _hash_api_key(api_key)
    with _connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT
                api_keys.id AS api_key_id,
                api_keys.key_hash,
                api_keys.status AS key_status,
                api_keys.expires_at,
                applications.id AS application_id,
                applications.slug,
                applications.name,
                applications.description,
                applications.status AS application_status,
                applications.created_at,
                applications.updated_at
            FROM api_keys
            JOIN applications ON applications.id = api_keys.application_id
            WHERE api_keys.key_hash = ?
            """,
            (key_hash,),
        ).fetchone()
        if row is None:
            return AuthenticationResult(False, reason="invalid_api_key")

        stored_hash = str(row["key_hash"]).encode("ascii")
        if not hmac.compare_digest(stored_hash, key_hash.encode("ascii")):
            return AuthenticationResult(False, reason="invalid_api_key")
        if row["key_status"] != "active":
            return AuthenticationResult(False, reason="revoked_api_key")
        if row["application_status"] != "active":
            return AuthenticationResult(False, reason="inactive_application")
        if row["expires_at"] is not None:
            try:
                expires_at = datetime.fromisoformat(row["expires_at"])
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                return AuthenticationResult(False, reason="invalid_api_key")
            if expires_at <= datetime.now(timezone.utc):
                return AuthenticationResult(False, reason="expired_api_key")

        used_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        connection.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
            (used_at, int(row["api_key_id"])),
        )
        application = {
            key: row[key]
            for key in (
                "application_id",
                "slug",
                "name",
                "description",
                "application_status",
                "created_at",
                "updated_at",
            )
        }
        application["id"] = application.pop("application_id")
        application["status"] = application.pop("application_status")
        return AuthenticationResult(
            True,
            application=application,
            api_key_id=int(row["api_key_id"]),
        )


def authenticate_flask_request(
    request, database_path: str | Path = DEFAULT_DATABASE_PATH
) -> AuthenticationResult:
    """Convenience adapter for a future Flask endpoint."""
    return authenticate_api_key(request.headers, database_path)

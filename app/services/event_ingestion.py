"""Normalization and retention handling for authenticated integration events."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from app.config import MAX_STORED_INPUT_LENGTH
from app.database import create_ingested_event
from app.services.analysis import analyze_security_input
from app.services.event_contract import SecurityEventContract


class EventAnalysisError(RuntimeError):
    """Raised when an accepted event cannot receive a security decision."""


_API_FIELDS = frozenset(
    {
        "event_type",
        "timestamp",
        "endpoint",
        "method",
        "http_method",
        "input_fields",
        "request_id",
        "metadata",
        "retention_mode",
        "application_slug",
    }
)


def _event_timestamp(value: object) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO-8601 string.")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("timestamp must be an ISO-8601 string.") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _apply_retention(
    input_fields: Mapping[str, str],
    metadata: Mapping[str, dict[str, str]],
    retention_mode: str,
) -> tuple[dict[str, str], dict[str, dict[str, str]], str]:
    combined = "\n".join(input_fields.values())
    if retention_mode == "full":
        stored_fields = dict(input_fields)
        stored_metadata = {key: dict(value) for key, value in metadata.items()}
        stored_input = combined
    elif retention_mode == "truncated":
        stored_fields = {
            key: value[:MAX_STORED_INPUT_LENGTH]
            for key, value in input_fields.items()
        }
        stored_metadata = {key: dict(value) for key, value in metadata.items()}
        stored_input = combined[:MAX_STORED_INPUT_LENGTH]
    elif retention_mode == "hash_only":
        stored_fields = {key: _digest(value) for key, value in input_fields.items()}
        stored_metadata = {
            key: {"value": _digest(value["value"]), "trust": value["trust"]}
            for key, value in metadata.items()
        }
        stored_input = _digest(combined)
    elif retention_mode == "redacted":
        stored_fields = {key: "[REDACTED]" for key in input_fields}
        stored_metadata = {
            key: {"value": "[REDACTED]", "trust": value["trust"]}
            for key, value in metadata.items()
        }
        stored_input = "[REDACTED]"
    else:
        stored_fields = {}
        stored_metadata = {}
        stored_input = ""
    return stored_fields, stored_metadata, stored_input


def normalize_ingestion_payload(
    payload: Mapping[str, object],
    *,
    application: Mapping[str, object],
) -> dict:
    if not isinstance(payload, Mapping):
        raise ValueError("Event payload must be a JSON object.")
    unknown = set(payload) - _API_FIELDS
    if unknown:
        raise ValueError("Event payload contains unsupported fields.")
    if "application_id" in payload:
        raise ValueError("application_id is not accepted.")

    normalized_payload = dict(payload)
    normalized_payload["application_slug"] = str(application["slug"])
    if "method" in normalized_payload:
        if "http_method" in normalized_payload:
            raise ValueError("Use method or http_method, not both.")
        normalized_payload["http_method"] = normalized_payload.pop("method")

    contract = SecurityEventContract.from_mapping(normalized_payload)
    metadata = {
        key: value.to_dict()
        for key, value in (contract.metadata or {}).items()
    }
    stored_fields, stored_metadata, stored_input = _apply_retention(
        contract.input_fields,
        metadata,
        contract.retention_mode,
    )
    return {
        "timestamp": _event_timestamp(payload.get("timestamp")),
        "application_id": int(application["id"]),
        "event_type": contract.event_type,
        "request_id": contract.request_id,
        "http_method": contract.http_method,
        "endpoint": contract.endpoint,
        "input_fields": stored_fields,
        "metadata": stored_metadata,
        "input_text": stored_input,
        "analysis_fields": dict(contract.input_fields),
        "retention_mode": contract.retention_mode,
    }


def persist_ingestion_event(
    payload: Mapping[str, object],
    *,
    application: Mapping[str, object],
    database_path: str | Path,
) -> dict:
    normalized = normalize_ingestion_payload(payload, application=application)
    try:
        normalized["analysis"] = analyze_security_input(normalized["analysis_fields"])
    except (KeyError, TypeError, ValueError, RuntimeError) as error:
        raise EventAnalysisError from error
    normalized.pop("analysis_fields")
    return create_ingested_event(normalized, database_path)

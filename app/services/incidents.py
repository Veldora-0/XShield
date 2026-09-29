"""Deterministic, bounded correlation of application security events."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any

from app.config import (
    INCIDENT_CORRELATION_WINDOW_SECONDS,
    INCIDENT_ENDPOINT_MATCH_ENABLED,
    INCIDENT_MAX_RECENT_EVENTS,
    INCIDENT_SINGLE_EVENT_RISK_LEVELS,
)
from app.database import get_recent_application_events
from app.services.behavior import analyze_behavior_context


_ENDPOINT_SEGMENT_RE = re.compile(
    r"^(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{16,})$",
    re.IGNORECASE,
)
_MULTIPLE_SLASHES_RE = re.compile(r"/{2,}")
_TRAILING_SLASH_RE = re.compile(r"/+$")


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _event_timestamp(event: Mapping[str, Any], fallback: datetime) -> datetime:
    return _parse_timestamp(event.get("timestamp")) or fallback


def _normalize_endpoint(endpoint: object) -> str | None:
    if not isinstance(endpoint, str):
        return None
    value = endpoint.split("?", 1)[0].split("#", 1)[0].strip()
    if not value:
        return None
    value = _MULTIPLE_SLASHES_RE.sub("/", value)
    if not value.startswith("/"):
        value = f"/{value}"
    segments = []
    for segment in value.split("/"):
        if not segment:
            continue
        segments.append(":id" if _ENDPOINT_SEGMENT_RE.fullmatch(segment) else segment[:64])
    normalized = "/" + "/".join(segments)
    return _TRAILING_SLASH_RE.sub("", normalized) or "/"


def _patterns(event: Mapping[str, Any]) -> set[str]:
    values = event.get("matched_rules")
    if not isinstance(values, Iterable) or isinstance(values, (str, bytes)):
        return set()
    return {str(value).strip() for value in values if str(value).strip()}


def _event_key(event: Mapping[str, Any]) -> str:
    event_id = event.get("id")
    if event_id is not None:
        return f"id:{event_id}"
    timestamp = str(event.get("timestamp", ""))
    request_id = str(event.get("request_id", ""))
    return f"event:{timestamp}:{request_id}"


def _same_application(event: Mapping[str, Any], application_id: int) -> bool:
    try:
        return int(event.get("application_id")) == int(application_id)
    except (TypeError, ValueError):
        return False


def _is_high_risk(event: Mapping[str, Any]) -> bool:
    return str(event.get("risk_level", "")) in INCIDENT_SINGLE_EVENT_RISK_LEVELS


def _bounded_candidates(
    application_id: int,
    current_event: Mapping[str, Any],
    recent_events: Iterable[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    fallback = datetime.now(timezone.utc)
    current_time = _event_timestamp(current_event, fallback)
    cutoff = current_time - timedelta(seconds=INCIDENT_CORRELATION_WINDOW_SECONDS)
    current_key = _event_key(current_event)
    candidates: list[tuple[datetime, int, Mapping[str, Any]]] = []
    for event in recent_events:
        if not isinstance(event, Mapping) or not _same_application(event, application_id):
            continue
        if _event_key(event) == current_key:
            continue
        event_time = _parse_timestamp(event.get("timestamp"))
        if event_time is None or event_time < cutoff or event_time > current_time:
            continue
        try:
            event_id = int(event.get("id", 0) or 0)
        except (TypeError, ValueError):
            event_id = 0
        candidates.append((event_time, event_id, event))
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [event for _, _, event in candidates[:INCIDENT_MAX_RECENT_EVENTS]]


def _relationship_reasons(
    current_event: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> list[str]:
    reasons: list[str] = []
    current_request_id = current_event.get("request_id")
    candidate_request_id = candidate.get("request_id")
    if current_request_id and current_request_id == candidate_request_id:
        reasons.append("shared request ID")

    if INCIDENT_ENDPOINT_MATCH_ENABLED:
        current_endpoint = _normalize_endpoint(current_event.get("endpoint"))
        candidate_endpoint = _normalize_endpoint(candidate.get("endpoint"))
        if current_endpoint and current_endpoint == candidate_endpoint:
            reasons.append("same normalized endpoint")

    shared_patterns = _patterns(current_event).intersection(_patterns(candidate))
    if shared_patterns:
        reasons.append(
            "overlapping detection patterns: " + ", ".join(sorted(shared_patterns))
        )

    if (
        reasons
        and current_event.get("event_type")
        and current_event.get("event_type") == candidate.get("event_type")
    ):
        reasons.append("compatible event type")
    return reasons


def _stable_incident_id(application_id: int, events: list[Mapping[str, Any]]) -> str:
    keys = sorted(_event_key(event) for event in events)
    payload = json.dumps(
        {"application_id": int(application_id), "events": keys},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    return f"inc_{digest}"


def correlate_incident(
    application_id: int,
    current_event: Mapping[str, Any],
    recent_events: Iterable[Mapping[str, Any]],
    *,
    behavior_context: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Correlate one event with bounded application-scoped recent history."""
    if not isinstance(current_event, Mapping):
        raise ValueError("current_event must be a mapping.")

    candidates = _bounded_candidates(application_id, current_event, recent_events)
    related: list[tuple[Mapping[str, Any], list[str]]] = []
    for candidate in candidates:
        reasons = _relationship_reasons(current_event, candidate)
        if reasons:
            related.append((candidate, reasons))

    current_is_single_event_incident = _is_high_risk(current_event)
    if not related and not current_is_single_event_incident:
        return None

    event_map = {_event_key(current_event): current_event}
    for candidate, _ in related:
        event_map[_event_key(candidate)] = candidate
    events = sorted(
        event_map.values(),
        key=lambda event: (
            _event_timestamp(event, datetime.now(timezone.utc)),
            str(event.get("id", "")),
        ),
    )
    relationship_reasons = sorted(
        {reason for _, reasons in related for reason in reasons}
    )
    if current_is_single_event_incident and not related:
        relationship_reasons.append(
            "single high-risk event qualifies under the configured incident rule"
        )

    timestamps = [
        _event_timestamp(event, datetime.now(timezone.utc)) for event in events
    ]
    endpoints = sorted(
        {
            endpoint
            for endpoint in (_normalize_endpoint(event.get("endpoint")) for event in events)
            if endpoint
        }
    )
    patterns = sorted(
        {pattern for event in events for pattern in _patterns(event)}
    )
    risk_levels = sorted(
        {str(event["risk_level"]) for event in events if event.get("risk_level")}
    )
    actions = sorted({str(event["action"]) for event in events if event.get("action")})
    event_types = sorted(
        {str(event["event_type"]) for event in events if event.get("event_type")}
    )
    behavior = dict(
        behavior_context
        if behavior_context is not None
        else analyze_behavior_context(application_id, current_event, candidates)
    )

    return {
        "incident_id": _stable_incident_id(application_id, events),
        "application_id": int(application_id),
        "event_ids": [
            event["id"] for event in events if event.get("id") is not None
        ],
        "started_at": min(timestamps).isoformat(timespec="seconds"),
        "latest_event_at": max(timestamps).isoformat(timespec="seconds"),
        "event_count": len(events),
        "risk_levels": risk_levels,
        "actions": actions,
        "event_types": event_types,
        "normalized_endpoints": endpoints,
        "matched_patterns": patterns,
        "behavior_context": behavior,
        "correlation_reasons": relationship_reasons,
        "correlation_window_seconds": INCIDENT_CORRELATION_WINDOW_SECONDS,
        "max_recent_events": INCIDENT_MAX_RECENT_EVENTS,
        "single_event_incident": len(events) == 1,
        "heuristic": True,
    }


def correlate_persisted_incident(
    application_id: int,
    current_event: Mapping[str, Any],
    database_path: str,
    *,
    behavior_context: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Load bounded application history and correlate the current event."""
    current_time = _event_timestamp(current_event, datetime.now(timezone.utc))
    cutoff = current_time - timedelta(seconds=INCIDENT_CORRELATION_WINDOW_SECONDS)
    recent_events = get_recent_application_events(
        application_id,
        cutoff.isoformat(timespec="seconds"),
        limit=INCIDENT_MAX_RECENT_EVENTS,
        database_path=database_path,
    )
    return correlate_incident(
        application_id,
        current_event,
        recent_events,
        behavior_context=behavior_context,
    )

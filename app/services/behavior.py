"""Bounded, explainable behavioral context signals for persisted events."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
import re
from typing import Any

from app.config import (
    BEHAVIOR_BURST_EVENT_THRESHOLD,
    BEHAVIOR_BURST_WINDOW_SECONDS,
    BEHAVIOR_ENDPOINT_REPETITION_THRESHOLD,
    BEHAVIOR_MAX_RECENT_EVENTS,
    BEHAVIOR_PATTERN_DIVERSITY_THRESHOLD,
    BEHAVIOR_REPEATED_SUSPICIOUS_THRESHOLD,
    BEHAVIOR_WINDOW_SECONDS,
)
from app.database import get_recent_application_events


_SUSPICIOUS_RISK_LEVELS = frozenset({"Medium", "High", "Critical"})
_ENDPOINT_SEGMENT_RE = re.compile(r"^(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{16,})$", re.IGNORECASE)
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


def _is_suspicious(event: Mapping[str, Any]) -> bool:
    if str(event.get("risk_level", "")) in _SUSPICIOUS_RISK_LEVELS:
        return True
    if str(event.get("action", "")) != "allow":
        return True
    return bool(event.get("rule_score", 0) or event.get("hybrid_signal", 0))


def _matched_patterns(event: Mapping[str, Any]) -> set[str]:
    matched_rules = event.get("matched_rules")
    if not isinstance(matched_rules, Iterable) or isinstance(matched_rules, (str, bytes)):
        return set()
    return {
        str(rule).strip()
        for rule in matched_rules
        if str(rule).strip()
    }


def _same_application(event: Mapping[str, Any], application_id: int) -> bool:
    try:
        return int(event.get("application_id")) == int(application_id)
    except (TypeError, ValueError):
        return False


def _bounded_history(
    application_id: int,
    current_event: Mapping[str, Any],
    recent_events: Iterable[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    current_time = _event_timestamp(current_event, datetime.now(timezone.utc))
    cutoff = current_time - timedelta(seconds=BEHAVIOR_WINDOW_SECONDS)
    current_id = current_event.get("id")
    candidates = []
    for event in recent_events:
        if not isinstance(event, Mapping) or not _same_application(event, application_id):
            continue
        if current_id is not None and event.get("id") == current_id:
            continue
        event_time = _parse_timestamp(event.get("timestamp"))
        if event_time is None or event_time < cutoff or event_time > current_time:
            continue
        candidates.append((event_time, int(event.get("id", 0) or 0), event))
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [event for _, _, event in candidates[:BEHAVIOR_MAX_RECENT_EVENTS]]


def analyze_behavior_context(
    application_id: int,
    current_event: Mapping[str, Any],
    recent_events: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Calculate deterministic behavioral signals without changing detection results."""
    if not isinstance(current_event, Mapping):
        raise ValueError("current_event must be a mapping.")

    history = _bounded_history(application_id, current_event, recent_events)
    current_time = _event_timestamp(current_event, datetime.now(timezone.utc))
    current_suspicious = _is_suspicious(current_event)
    suspicious_events = [event for event in history if _is_suspicious(event)]
    considered_events = [*history, current_event]
    suspicious_considered = [*suspicious_events] + (
        [current_event] if current_suspicious else []
    )

    repeated_activity = (
        len(suspicious_considered) >= BEHAVIOR_REPEATED_SUSPICIOUS_THRESHOLD
    )
    current_endpoint = _normalize_endpoint(current_event.get("endpoint"))
    endpoint_matches = [
        event
        for event in suspicious_events
        if current_endpoint is not None
        and _normalize_endpoint(event.get("endpoint")) == current_endpoint
    ]
    endpoint_repetition = (
        current_endpoint is not None
        and len(endpoint_matches) + (1 if current_suspicious else 0)
        >= BEHAVIOR_ENDPOINT_REPETITION_THRESHOLD
    )

    burst_cutoff = current_time - timedelta(seconds=BEHAVIOR_BURST_WINDOW_SECONDS)
    burst_events = [
        event
        for event in considered_events
        if burst_cutoff <= _event_timestamp(event, current_time) <= current_time
    ]
    burst_activity = len(burst_events) >= BEHAVIOR_BURST_EVENT_THRESHOLD

    patterns: set[str] = set()
    for event in suspicious_considered:
        patterns.update(_matched_patterns(event))
    pattern_diversity = len(patterns) >= BEHAVIOR_PATTERN_DIVERSITY_THRESHOLD

    score = 0
    reasons: list[str] = []
    if repeated_activity:
        score += 30
        reasons.append(
            "Repeated suspicious activity met the configured threshold."
        )
    if endpoint_repetition:
        score += 25
        reasons.append(
            "Suspicious activity repeatedly targeted the normalized endpoint."
        )
    if burst_activity:
        score += 25
        reasons.append("Event frequency met the configured burst threshold.")
    if pattern_diversity:
        score += 20
        reasons.append(
            "Recent suspicious events contained multiple detection patterns."
        )

    return {
        "behavioral_score": min(score, 100),
        "repeated_activity": repeated_activity,
        "burst_activity": burst_activity,
        "endpoint_repetition": endpoint_repetition,
        "pattern_diversity": pattern_diversity,
        "recent_event_count": len(history),
        "recent_suspicious_event_count": len(suspicious_events),
        "normalized_endpoint": current_endpoint,
        "pattern_count": len(patterns),
        "reasons": reasons,
        "window_seconds": BEHAVIOR_WINDOW_SECONDS,
        "burst_window_seconds": BEHAVIOR_BURST_WINDOW_SECONDS,
        "max_recent_events": BEHAVIOR_MAX_RECENT_EVENTS,
        "heuristic": True,
    }


def analyze_persisted_behavior_context(
    application_id: int,
    current_event: Mapping[str, Any],
    database_path: str,
) -> dict[str, Any]:
    """Load a bounded application history, then calculate context signals."""
    current_time = _event_timestamp(current_event, datetime.now(timezone.utc))
    cutoff = current_time - timedelta(seconds=BEHAVIOR_WINDOW_SECONDS)
    recent_events = get_recent_application_events(
        application_id,
        cutoff.isoformat(timespec="seconds"),
        limit=BEHAVIOR_MAX_RECENT_EVENTS,
        database_path=database_path,
    )
    return analyze_behavior_context(application_id, current_event, recent_events)

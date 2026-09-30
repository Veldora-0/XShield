"""Bounded data assembly for the authenticated security dashboard."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from app.database.db import (
    DEFAULT_DATABASE_PATH,
    get_dashboard_stats,
    get_filtered_events,
    list_applications,
)
from app.services.api_keys import list_api_keys
from app.services.behavior import analyze_behavior_context
from app.services.incidents import correlate_incident


def _application_name(
    event: Mapping[str, Any],
    applications: Mapping[int, Mapping[str, Any]],
) -> str:
    try:
        application = applications.get(int(event.get("application_id")))
    except (TypeError, ValueError):
        application = None
    return str(application["name"]) if application else "Unassigned"


def _incident_risk(incident: Mapping[str, Any]) -> str:
    levels = incident.get("risk_levels", [])
    order = ("Critical", "High", "Medium", "Low")
    return next((level for level in order if level in levels), "Low")


def _derive_incidents(
    events: list[dict[str, Any]],
    applications: Mapping[int, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    incidents: dict[str, dict[str, Any]] = {}
    for event in events:
        try:
            application_id = int(event["application_id"])
        except (KeyError, TypeError, ValueError):
            continue
        incident = correlate_incident(application_id, event, events)
        if incident is None:
            continue
        incident = dict(incident)
        incident["application_name"] = _application_name(event, applications)
        incident["risk_level"] = _incident_risk(incident)
        incidents[incident["incident_id"]] = incident
    return sorted(
        incidents.values(),
        key=lambda incident: incident["latest_event_at"],
        reverse=True,
    )


def _behavior_summary(contexts: list[Mapping[str, Any]]) -> dict[str, Any]:
    if not contexts:
        return {
            "behavioral_score": 0,
            "repeated_activity": False,
            "endpoint_repetition": False,
            "burst_activity": False,
            "pattern_diversity": False,
            "recent_event_count": 0,
            "reasons": [],
        }
    latest = contexts[0]
    return {
        "behavioral_score": max(
            int(context.get("behavioral_score", 0) or 0) for context in contexts
        ),
        "repeated_activity": any(
            bool(context.get("repeated_activity")) for context in contexts
        ),
        "endpoint_repetition": any(
            bool(context.get("endpoint_repetition")) for context in contexts
        ),
        "burst_activity": any(
            bool(context.get("burst_activity")) for context in contexts
        ),
        "pattern_diversity": any(
            bool(context.get("pattern_diversity")) for context in contexts
        ),
        "recent_event_count": max(
            int(context.get("recent_event_count", 0) or 0) for context in contexts
        ),
        "reasons": list(latest.get("reasons", [])),
    }


def get_dashboard_snapshot(
    *,
    limit: int = 50,
    risk_level: str | None = None,
    action: str | None = None,
    search: str | None = None,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> dict[str, Any]:
    """Return bounded, presentation-ready dashboard data without secrets."""
    applications = list_applications(database_path)
    application_map = {int(app["id"]): app for app in applications}
    events = get_filtered_events(
        limit=limit,
        risk_level=risk_level,
        action=action,
        search=search,
        database_path=database_path,
    )
    stats = get_dashboard_stats(database_path)
    key_metadata = list_api_keys(database_path)
    keys_by_application: dict[int, list[dict[str, Any]]] = {}
    for key in key_metadata:
        keys_by_application.setdefault(int(key["application_id"]), []).append(key)

    application_rows = []
    for application in applications:
        keys = keys_by_application.get(int(application["id"]), [])
        active_keys = sum(key["status"] == "active" for key in keys)
        application_rows.append(
            {
                **application,
                "api_key_count": len(keys),
                "active_api_key_count": active_keys,
            }
        )

    incidents = _derive_incidents(events, application_map)
    behavior_contexts = []
    for event in events:
        try:
            application_id = int(event["application_id"])
        except (KeyError, TypeError, ValueError):
            continue
        behavior_contexts.append(
            analyze_behavior_context(application_id, event, events)
        )
    return {
        "stats": {
            **stats,
            "application_count": len(applications),
        },
        "events": [
            {
                **event,
                "application_name": _application_name(event, application_map),
            }
            for event in events
        ],
        "applications": application_rows,
        "incidents": incidents[:12],
        "behavior": _behavior_summary(behavior_contexts),
        "event_limit": limit,
    }

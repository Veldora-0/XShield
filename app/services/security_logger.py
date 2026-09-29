import json
import sqlite3
from collections.abc import Mapping
from pathlib import Path

from app.database.db import create_security_event


def _event_from_pipeline(
    input_text: str,
    detection_result: Mapping[str, object],
) -> dict:
    rule_result = detection_result["rule_result"]
    ml_result = detection_result["ml_result"]
    hybrid = detection_result["hybrid"]
    risk_result = detection_result["risk_result"]
    action_result = detection_result["action_result"]
    return {
        "input_text": input_text,
        "rule_score": rule_result["score"],
        "ml_probability": ml_result["probability"],
        "ml_prediction": ml_result["prediction"],
        "hybrid_signal": hybrid["hybrid_signal"],
        "risk_score": risk_result["risk_score"],
        "risk_level": risk_result["risk_level"],
        "action": action_result["action"],
        "detector_agreement": hybrid["agreement"],
        "matched_rules": rule_result.get("matched_rules", []),
        "reasons": risk_result.get("reasons", []),
    }


def log_security_event(
    input_text: str,
    detection_result: Mapping[str, object],
    database_path: str | Path,
) -> dict:
    """Log the completed pipeline and return explicit persistence status."""
    try:
        result = create_security_event(
            _event_from_pipeline(input_text, detection_result),
            database_path,
        )
    except (
        KeyError,
        TypeError,
        ValueError,
        OSError,
        sqlite3.Error,
        json.JSONDecodeError,
    ) as error:
        return {
            "stored": False,
            "error": (
                "Security event was not stored. The detection result remains "
                "available, but the database write should be investigated."
            ),
        }
    return {
        "stored": True,
        "event_id": result["id"],
        "timestamp": result["timestamp"],
    }

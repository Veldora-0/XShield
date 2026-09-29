"""Shared orchestration for XShield security analysis."""

from __future__ import annotations

from collections.abc import Mapping

from app.detector import detect_hybrid_fields
from app.response import assess_action
from app.risk import assess_risk


def analyze_security_input(fields: Mapping[str, str]) -> dict:
    """Run the existing hybrid, risk, and action layers exactly once."""
    if not isinstance(fields, Mapping) or not fields:
        raise ValueError("Analysis input must contain at least one field.")

    hybrid_result = detect_hybrid_fields(fields)
    risk_result = assess_risk(hybrid_result)
    action_result = assess_action(risk_result)
    return {
        **hybrid_result,
        "risk_result": risk_result,
        "action_result": action_result,
        "analysis_field_names": list(fields.keys()),
    }

from collections.abc import Mapping

from app.risk.risk_engine import (
    HIGH_MAX,
    LOW_MAX,
    MEDIUM_MAX,
)


# Project-defined prototype policy. These actions are application behavior,
# not universal cybersecurity standards.
RESPONSE_POLICY = {
    "Low": "allow",
    "Medium": "flag",
    "High": "block",
    "Critical": "block_and_alert",
}

BLOCKING_ACTIONS = frozenset({"block", "block_and_alert"})


def _validate_risk_result(risk_result: Mapping[str, object]) -> tuple[str, float]:
    try:
        risk_level = str(risk_result["risk_level"])
        risk_score = float(risk_result["risk_score"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Invalid risk result structure.") from error

    if risk_level not in RESPONSE_POLICY:
        raise ValueError(f"Unsupported risk level: {risk_level}")
    if not 0 <= risk_score <= 100:
        raise ValueError("Risk score must be between 0 and 100.")
    expected_level = (
        "Low"
        if risk_score <= LOW_MAX
        else "Medium"
        if risk_score <= MEDIUM_MAX
        else "High"
        if risk_score <= HIGH_MAX
        else "Critical"
    )
    if risk_level != expected_level:
        raise ValueError(
            f"Risk score {risk_score:g} is inconsistent with risk level "
            f"{risk_level}; expected {expected_level}."
        )
    return risk_level, risk_score


def assess_action(risk_result: Mapping[str, object]) -> dict:
    """Map a Phase 9 risk result to the configured application action."""
    if not isinstance(risk_result, Mapping):
        raise ValueError("Risk result must be a mapping.")

    risk_level, risk_score = _validate_risk_result(risk_result)
    action = RESPONSE_POLICY[risk_level]
    blocked = action in BLOCKING_ACTIONS
    alert_required = action == "block_and_alert"

    if action == "allow":
        action_message = (
            "Input may continue through the safe demo flow. "
            "It remains untrusted and is displayed only as escaped text."
        )
    elif action == "flag":
        action_message = (
            "Input is flagged for attention and may continue only through "
            "the safe escaped-text demo flow."
        )
    elif action == "block":
        action_message = (
            "Input was rejected by the local demonstration because its risk "
            "level requires blocking."
        )
    else:
        action_message = (
            "Input was rejected by the local demonstration. Its risk level "
            "requires blocking and would require a future alert."
        )

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "action": action,
        "action_message": action_message,
        "reason": (
            f"Risk level is {risk_level} according to the configured "
            "prototype response policy."
        ),
        "blocked": blocked,
        "alert_required": alert_required,
    }

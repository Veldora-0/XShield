from collections.abc import Mapping


# These are configurable project parameters, not industry-standard thresholds.
LOW_MAX = 29
MEDIUM_MAX = 59
HIGH_MAX = 79
CRITICAL_MAX = 100


def _clamp_score(score: float) -> float:
    return max(0.0, min(float(score), float(CRITICAL_MAX)))


def _clamp_signal(signal: float) -> float:
    return max(0.0, min(float(signal), 1.0))


def _risk_level(score: float) -> str:
    if score <= LOW_MAX:
        return "Low"
    if score <= MEDIUM_MAX:
        return "Medium"
    if score <= HIGH_MAX:
        return "High"
    return "Critical"


def _build_reasons(hybrid_result: Mapping[str, object], risk_level: str) -> list[str]:
    rule_result = hybrid_result["rule_result"]
    ml_result = hybrid_result["ml_result"]
    hybrid = hybrid_result["hybrid"]

    reasons = [
        (
            f"Hybrid signal {float(hybrid['hybrid_signal']):.4f} was converted "
            f"to a {risk_level} risk score."
        ),
        (
            f"Rule detector score: {rule_result['score']}/100; "
            f"normalized contribution: {float(hybrid['rule_contribution']):.4f}."
        ),
        (
            f"ML detector prediction: {ml_result['prediction']}; "
            f"XSS probability: {float(ml_result['probability']):.4f}; "
            f"contribution: {float(hybrid['ml_contribution']):.4f}."
        ),
        f"Detector agreement: {hybrid['agreement']}.",
    ]

    for indicator in rule_result.get("risk_indicators", []):
        reasons.append(f"Rule indicator: {indicator}")
    return reasons


def assess_risk(hybrid_result: Mapping[str, object]) -> dict:
    """Convert the Phase 8 hybrid signal into an explainable risk result."""
    try:
        hybrid = hybrid_result["hybrid"]
        hybrid_signal = float(hybrid["hybrid_signal"])
        rule_result = hybrid_result["rule_result"]
        ml_result = hybrid_result["ml_result"]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Invalid hybrid result structure.") from error

    if not isinstance(rule_result, Mapping) or not isinstance(ml_result, Mapping):
        raise ValueError("Hybrid detector results must contain mapping values.")

    # Phase 8 emits a 0.0–1.0 signal. Clamp defensively before converting it
    # to the project-defined 0–100 risk-score scale.
    hybrid_signal = _clamp_signal(hybrid_signal)
    risk_score = round(_clamp_score(hybrid_signal * 100), 2)
    risk_level = _risk_level(risk_score)

    components = {
        "rule_score": float(rule_result["score"]),
        "normalized_rule_score": float(hybrid["rule_score_normalized"]),
        "ml_probability": float(ml_result["probability"]),
        "hybrid_signal": hybrid_signal,
        "rule_weight": float(hybrid["rule_weight"]),
        "ml_weight": float(hybrid["ml_weight"]),
        "rule_contribution": float(hybrid["rule_contribution"]),
        "ml_contribution": float(hybrid["ml_contribution"]),
        "agreement": hybrid["agreement"],
    }

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "components": components,
        "explainability": {
            "matched_rules": list(rule_result.get("matched_rules", [])),
            "rule_details": list(rule_result.get("rule_details", [])),
            "rule_reasons": list(rule_result.get("risk_indicators", [])),
            "ml_prediction": ml_result["prediction"],
            "ml_probability": float(ml_result["probability"]),
            "agreement": hybrid["agreement"],
        },
        "reasons": _build_reasons(hybrid_result, risk_level),
    }

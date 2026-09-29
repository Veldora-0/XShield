from collections.abc import Mapping

from app.detector.rule_engine import detect_text as detect_rule_text
from app.ml.predictor import predict_text


DEFAULT_RULE_WEIGHT = 0.5
DEFAULT_ML_WEIGHT = 0.5


def _validate_weights(rule_weight: float, ml_weight: float) -> tuple[float, float]:
    rule_weight = float(rule_weight)
    ml_weight = float(ml_weight)
    if rule_weight < 0 or ml_weight < 0:
        raise ValueError("Hybrid detector weights cannot be negative.")
    total = rule_weight + ml_weight
    if total <= 0:
        raise ValueError("At least one hybrid detector weight must be positive.")
    return rule_weight / total, ml_weight / total


def _agreement(rule_suspicious: bool, ml_is_xss: bool) -> str:
    if rule_suspicious and ml_is_xss:
        return "both_suspicious"
    if rule_suspicious:
        return "rule_only"
    if ml_is_xss:
        return "ml_only"
    return "both_benign"


def detect_text(
    value: str,
    *,
    rule_weight: float = DEFAULT_RULE_WEIGHT,
    ml_weight: float = DEFAULT_ML_WEIGHT,
) -> dict:
    """Run the independent rule and ML detectors, then combine their signals."""
    rule_weight, ml_weight = _validate_weights(rule_weight, ml_weight)
    text = str(value)
    rule_result = detect_rule_text(text)
    ml_result = predict_text(text)

    normalized_rule_score = max(0.0, min(1.0, rule_result["score"] / 100))
    ml_score = max(0.0, min(1.0, float(ml_result["probability"])))
    hybrid_signal = max(
        0.0,
        min(
            1.0,
            (rule_weight * normalized_rule_score) + (ml_weight * ml_score),
        ),
    )

    return {
        "rule_result": rule_result,
        "ml_result": ml_result,
        "hybrid": {
            "rule_score_normalized": normalized_rule_score,
            "ml_score": ml_score,
            "rule_weight": rule_weight,
            "ml_weight": ml_weight,
            "rule_contribution": rule_weight * normalized_rule_score,
            "ml_contribution": ml_weight * ml_score,
            "hybrid_signal": hybrid_signal,
            "agreement": _agreement(
                rule_result["is_suspicious"],
                ml_result["label"] == 1,
            ),
        },
    }


def detect_fields(
    fields: Mapping[str, str],
    *,
    rule_weight: float = DEFAULT_RULE_WEIGHT,
    ml_weight: float = DEFAULT_ML_WEIGHT,
) -> dict:
    """Analyze submitted form fields as one safely combined input."""
    combined_text = "\n".join(str(value) for value in fields.values())
    result = detect_text(
        combined_text,
        rule_weight=rule_weight,
        ml_weight=ml_weight,
    )
    return {**result, "field_names": list(fields.keys())}

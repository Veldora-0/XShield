from collections.abc import Mapping

from app.detector.rules import RULES, AnalysisContext, RuleMatch, normalize_input


def detect_text(value: str) -> dict:
    """Analyze one text value and return an explainable baseline result."""
    context = normalize_input(value)
    matched_ids = set()
    matches = []

    for rule in RULES:
        if rule.rule_id == "R006":
            continue
        if rule.detector(context, matched_ids):
            matched_ids.add(rule.rule_id)
            matches.append(
                RuleMatch(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    description=rule.description,
                    weight=rule.weight,
                    reason=rule.reason,
                )
            )

    combination_rule = next(rule for rule in RULES if rule.rule_id == "R006")
    if combination_rule.detector(context, matched_ids):
        matched_ids.add(combination_rule.rule_id)
        matches.append(
            RuleMatch(
                rule_id=combination_rule.rule_id,
                name=combination_rule.name,
                description=combination_rule.description,
                weight=combination_rule.weight,
                reason=combination_rule.reason,
            )
        )

    score = min(100, sum(match.weight for match in matches))
    return {
        "score": score,
        "is_suspicious": bool(matches),
        "matched_rules": [match.rule_id for match in matches],
        "risk_indicators": [match.reason for match in matches],
        "rule_details": [match.__dict__ for match in matches],
    }


def detect_fields(fields: Mapping[str, str]) -> dict:
    """Analyze multiple form fields and retain which field triggered each rule."""
    field_results = {
        field_name: detect_text(value)
        for field_name, value in fields.items()
    }
    score = min(100, sum(result["score"] for result in field_results.values()))
    matched_rules = []
    indicators = []
    details = []

    for field_name, result in field_results.items():
        for detail in result["rule_details"]:
            qualified_id = f"{field_name}:{detail['rule_id']}"
            matched_rules.append(qualified_id)
            indicators.append(f"{field_name}: {detail['reason']}")
            details.append({**detail, "field": field_name})

    return {
        "score": score,
        "is_suspicious": bool(matched_rules),
        "matched_rules": matched_rules,
        "risk_indicators": indicators,
        "rule_details": details,
    }

import html
import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import unquote


MAX_ANALYSIS_LENGTH = 10_000


@dataclass(frozen=True)
class AnalysisContext:
    """Normalized views of one input used by the independent rules."""

    original: str
    normalized: str
    decoded: str


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    name: str
    description: str
    weight: int
    reason: str


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    name: str
    description: str
    weight: int
    detector: Callable[[AnalysisContext, set[str]], bool]
    reason: str


def normalize_input(value: str) -> AnalysisContext:
    """Create bounded, case-insensitive views without executing or rendering input."""
    original = value[:MAX_ANALYSIS_LENGTH]
    normalized = re.sub(r"\s+", " ", original).strip().casefold()

    # Decode one layer only so encoded indicators can be recognized without
    # repeatedly transforming attacker-controlled data.
    decoded = html.unescape(unquote(normalized))
    return AnalysisContext(
        original=original,
        normalized=normalized,
        decoded=decoded,
    )


def _has_markup(context: AnalysisContext, _: set[str]) -> bool:
    return bool(re.search(r"<\s*/?\s*[a-z][^>]*>", context.decoded))


def _has_script_construct(context: AnalysisContext, _: set[str]) -> bool:
    return bool(
        re.search(
            r"<\s*script\b|</\s*script\s*>|\b(?:eval|settimeout|setinterval)\s*\(",
            context.decoded,
        )
    )


def _has_event_handler(context: AnalysisContext, _: set[str]) -> bool:
    return bool(re.search(r"\bon[a-z][a-z0-9_-]*\s*=", context.decoded))


def _has_dangerous_scheme(context: AnalysisContext, _: set[str]) -> bool:
    return bool(re.search(r"\b(?:javascript|vbscript|data)\s*:", context.decoded))


def _has_encoded_indicator(context: AnalysisContext, _: set[str]) -> bool:
    encoded_marker = re.search(
        r"(?:%3c|%3e|%22|%27|&#x?[0-9a-f]+;)", context.normalized
    )
    decoded_indicator = re.search(
        r"<\s*(?:script|iframe|img|svg|object|a\b)|\bon[a-z][a-z0-9_-]*\s*=|"
        r"\b(?:javascript|vbscript|data)\s*:",
        context.decoded,
    )
    return bool(encoded_marker and decoded_indicator)


def _has_multiple_indicators(context: AnalysisContext, matched_ids: set[str]) -> bool:
    del context
    base_rules = {
        "R001",
        "R002",
        "R003",
        "R004",
        "R005",
    }
    return len(matched_ids.intersection(base_rules)) >= 2


RULES = (
    DetectionRule(
        rule_id="R001",
        name="Unexpected HTML markup",
        description="Detects HTML-like tags inside an input field.",
        weight=12,
        detector=_has_markup,
        reason="HTML-like markup was found in the submitted text.",
    ),
    DetectionRule(
        rule_id="R002",
        name="Script-related construct",
        description="Detects script tags and common script execution function patterns.",
        weight=30,
        detector=_has_script_construct,
        reason="A script-related construct was found in the submitted text.",
    ),
    DetectionRule(
        rule_id="R003",
        name="Event-handler attribute",
        description="Detects attributes that resemble browser event handlers.",
        weight=25,
        detector=_has_event_handler,
        reason="An event-handler-style attribute was found in the submitted text.",
    ),
    DetectionRule(
        rule_id="R004",
        name="Suspicious URL scheme",
        description="Detects schemes commonly associated with script-capable URLs.",
        weight=25,
        detector=_has_dangerous_scheme,
        reason="A potentially script-capable URL scheme was found in the submitted text.",
    ),
    DetectionRule(
        rule_id="R005",
        name="Encoded suspicious representation",
        description="Detects encoded characters that decode into suspicious constructs.",
        weight=15,
        detector=_has_encoded_indicator,
        reason="Encoded characters decoded into a suspicious construct.",
    ),
    DetectionRule(
        rule_id="R006",
        name="Multiple suspicious indicators",
        description="Adds context when multiple independent indicators occur together.",
        weight=15,
        detector=_has_multiple_indicators,
        reason="Multiple independent suspicious characteristics occurred together.",
    ),
)

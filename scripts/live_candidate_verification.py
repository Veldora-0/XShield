"""Production Integration and Realistic Live Testing for Candidate V2.

Verifies that Candidate V2 drops cleanly into XShield's 5-stage architecture:
Input -> Rule Detector -> ML Detector -> Hybrid Fusion (50/50) -> Risk Engine -> Action Engine.
Evaluates representative payloads across all 8 qualitative categories and outputs exact signals.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

import joblib

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.detector.rule_engine import detect_text as detect_rule_text
from app.response.action_engine import assess_action
from app.risk.risk_engine import assess_risk
from scripts.qualitative_suite import QUALITATIVE_TEST_CASES

CANDIDATE_MODEL_PATH = PROJECT_ROOT / "models" / "candidate_v2" / "xss_logistic_regression.joblib"
CANDIDATE_VEC_PATH = PROJECT_ROOT / "models" / "candidate_v2" / "xss_tfidf_vectorizer.joblib"
OUTPUT_REPORT = PROJECT_ROOT / "reports" / "candidate_v2" / "live_predictions.json"


def test_production_pipeline_compatibility() -> dict[str, Any]:
    print("=" * 70)
    print("PHASE 8 & 9: PRODUCTION PIPELINE INTEGRATION & LIVE CANDIDATE TESTING")
    print("=" * 70)

    # 1. Verify artifact loading
    assert CANDIDATE_MODEL_PATH.exists(), f"Missing candidate model at {CANDIDATE_MODEL_PATH}"
    assert CANDIDATE_VEC_PATH.exists(), f"Missing candidate vectorizer at {CANDIDATE_VEC_PATH}"

    candidate_model = joblib.load(CANDIDATE_MODEL_PATH)
    candidate_vec = joblib.load(CANDIDATE_VEC_PATH)
    print("[OK] Successfully loaded Candidate V2 model and vectorizer artifacts.")

    # 2. Build pipeline emulator with exact production fusion weights (0.5 Rule, 0.5 ML)
    def run_pipeline(payload: str) -> dict[str, Any]:
        # Stage 1: Rule Detector
        rule_res = detect_rule_text(payload)

        # Stage 2: Candidate ML Detector
        vec = candidate_vec.transform([payload])
        prob = float(candidate_model.predict_proba(vec)[0, 1])
        ml_res = {
            "prediction": "xss" if prob >= 0.5 else "benign",
            "probability": prob,
            "label": 1 if prob >= 0.5 else 0,
        }

        # Stage 3: Hybrid Fusion (50% Rule, 50% ML)
        norm_rule = max(0.0, min(1.0, rule_res["score"] / 100.0))
        hybrid_signal = max(0.0, min(1.0, 0.5 * norm_rule + 0.5 * prob))
        agreement = (
            "both_suspicious" if rule_res["is_suspicious"] and prob >= 0.5
            else "rule_only" if rule_res["is_suspicious"]
            else "ml_only" if prob >= 0.5
            else "both_benign"
        )
        hybrid_dict = {
            "rule_result": rule_res,
            "ml_result": ml_res,
            "hybrid": {
                "rule_score_normalized": norm_rule,
                "ml_score": prob,
                "rule_weight": 0.5,
                "ml_weight": 0.5,
                "rule_contribution": 0.5 * norm_rule,
                "ml_contribution": 0.5 * prob,
                "hybrid_signal": hybrid_signal,
                "agreement": agreement,
            },
        }

        # Stage 4: Risk Engine (0-100 scale, Low/Medium/High/Critical)
        risk_res = assess_risk(hybrid_dict)

        # Stage 5: Action Engine (allow / flag / block / block_and_alert)
        action_res = assess_action(risk_res)

        return {
            "payload": payload,
            "rule_score": rule_res["score"],
            "rule_suspicious": rule_res["is_suspicious"],
            "ml_probability": round(prob, 4),
            "ml_prediction": ml_res["prediction"],
            "hybrid_signal": round(hybrid_signal, 4),
            "risk_score": risk_res["risk_score"],
            "risk_level": risk_res["risk_level"],
            "action": action_res["action"],
            "blocked": action_res["blocked"],
        }

    # 3. Live test across qualitative categories
    live_records = []
    print("\nEvaluating Live Representative Payloads Across 8 Categories:")
    print("-" * 70)
    print(f"{'Category':<15} | {'ML Prob':<8} | {'Rule':<5} | {'Risk':<8} | {'Action':<15} | {'Payload Preview':<20}")
    print("-" * 70)

    for case in QUALITATIVE_TEST_CASES:
        res = run_pipeline(case.payload)
        preview = (case.payload[:20] + "...") if len(case.payload) > 20 else case.payload
        print(f"{case.category_name[:15]:<15} | {res['ml_probability']:<8.4f} | {res['rule_score']:<5} | {res['risk_level']:<8} | {res['action']:<15} | {preview}")
        live_records.append({
            "id": case.id,
            "category": case.category,
            "category_name": case.category_name,
            "expected_label": case.expected_label,
            "result": res,
        })

    print("-" * 70)
    OUTPUT_REPORT.write_text(json.dumps(live_records, indent=2), encoding="utf-8")
    print(f"\n[SUCCESS] Live predictions saved to {OUTPUT_REPORT}")
    return {"status": "SUCCESS", "records": live_records}


if __name__ == "__main__":
    test_production_pipeline_compatibility()

import unittest
from unittest.mock import patch

from app import create_app
from app.detector.hybrid_detector import detect_fields, detect_text


class HybridDetectorTests(unittest.TestCase):
    def test_result_contains_both_detector_outputs_and_hybrid_components(self):
        result = detect_text("ordinary feedback")

        self.assertIn("rule_result", result)
        self.assertIn("ml_result", result)
        self.assertIn("hybrid", result)
        self.assertIn("matched_rules", result["rule_result"])
        self.assertIn("probability", result["ml_result"])
        self.assertGreaterEqual(result["hybrid"]["hybrid_signal"], 0.0)
        self.assertLessEqual(result["hybrid"]["hybrid_signal"], 1.0)

    def test_detector_invokes_rule_and_ml_layers(self):
        rule_result = {
            "score": 40,
            "is_suspicious": True,
            "matched_rules": ["R001"],
            "risk_indicators": ["markup"],
            "rule_details": [],
        }
        ml_result = {"label": 1, "prediction": "xss", "probability": 0.8}
        with patch(
            "app.detector.hybrid_detector.detect_rule_text",
            return_value=rule_result,
        ) as rule_detector, patch(
            "app.detector.hybrid_detector.predict_text",
            return_value=ml_result,
        ) as ml_detector:
            result = detect_text("test input")

        rule_detector.assert_called_once_with("test input")
        ml_detector.assert_called_once_with("test input")
        self.assertEqual(result["hybrid"]["agreement"], "both_suspicious")
        self.assertAlmostEqual(result["hybrid"]["hybrid_signal"], 0.6)

    def test_agreement_states_are_based_on_actual_outputs(self):
        cases = [
            (False, 0, "both_benign"),
            (True, 0, "rule_only"),
            (False, 1, "ml_only"),
            (True, 1, "both_suspicious"),
        ]
        for suspicious, label, expected in cases:
            with self.subTest(expected=expected), patch(
                "app.detector.hybrid_detector.detect_rule_text",
                return_value={
                    "score": 20 if suspicious else 0,
                    "is_suspicious": suspicious,
                    "matched_rules": [],
                    "risk_indicators": [],
                    "rule_details": [],
                },
            ), patch(
                "app.detector.hybrid_detector.predict_text",
                return_value={
                    "label": label,
                    "prediction": "xss" if label else "benign",
                    "probability": 0.8 if label else 0.1,
                },
            ):
                result = detect_text("")
            self.assertEqual(result["hybrid"]["agreement"], expected)

    def test_weights_are_normalized_and_invalid_weights_are_rejected(self):
        result = detect_text("test", rule_weight=2, ml_weight=1)
        self.assertAlmostEqual(result["hybrid"]["rule_weight"], 2 / 3)
        self.assertAlmostEqual(result["hybrid"]["ml_weight"], 1 / 3)
        with self.assertRaises(ValueError):
            detect_text("test", rule_weight=-1, ml_weight=1)
        with self.assertRaises(ValueError):
            detect_text("test", rule_weight=0, ml_weight=0)

    def test_empty_input_returns_a_valid_result(self):
        result = detect_text("")
        self.assertIn(result["hybrid"]["agreement"], {
            "both_benign",
            "rule_only",
            "ml_only",
            "both_suspicious",
        })
        self.assertGreaterEqual(result["ml_result"]["probability"], 0.0)
        self.assertLessEqual(result["ml_result"]["probability"], 1.0)

    def test_field_integration_keeps_field_names(self):
        result = detect_fields({"username": "student", "comment": "feedback"})
        self.assertEqual(result["field_names"], ["username", "comment"])
        self.assertIn("rule_result", result)
        self.assertIn("ml_result", result)

    def test_flask_displays_rule_ml_and_hybrid_sections(self):
        client = create_app().test_client()
        response = client.post(
            "/",
            data={
                "username": "student_01",
                "search_query": "security",
                "comment": '<img src="javascript:demo" onerror="run()">',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"RULE DETECTOR", response.data)
        self.assertIn(b"ML DETECTOR", response.data)
        self.assertIn(b"HYBRID SIGNAL", response.data)
        self.assertIn(b"AGREEMENT", response.data)
        self.assertIn(b"RESPONSE ACTION", response.data)
        self.assertIn(b"rejected it", response.data)
        self.assertNotIn(b"&lt;img", response.data)
        self.assertNotIn(b"<img src=", response.data)


if __name__ == "__main__":
    unittest.main()

import unittest

from app.risk import assess_risk


def hybrid_result(signal: float) -> dict:
    return {
        "rule_result": {
            "score": 40,
            "is_suspicious": True,
            "matched_rules": ["R001"],
            "risk_indicators": ["HTML-like markup was found."],
            "rule_details": [{"rule_id": "R001", "name": "Markup"}],
        },
        "ml_result": {
            "label": 1,
            "prediction": "xss",
            "probability": 0.8,
        },
        "hybrid": {
            "rule_score_normalized": 0.4,
            "ml_score": 0.8,
            "rule_weight": 0.5,
            "ml_weight": 0.5,
            "rule_contribution": 0.2,
            "ml_contribution": 0.4,
            "hybrid_signal": signal,
            "agreement": "both_suspicious",
        },
    }


class RiskEngineTests(unittest.TestCase):
    def test_threshold_boundaries(self):
        expected = {
            0: "Low",
            29: "Low",
            30: "Medium",
            59: "Medium",
            60: "High",
            79: "High",
            80: "Critical",
            100: "Critical",
        }
        for score, level in expected.items():
            with self.subTest(score=score):
                result = assess_risk(hybrid_result(score / 100))
                self.assertEqual(result["risk_score"], score)
                self.assertEqual(result["risk_level"], level)

    def test_out_of_range_signals_are_clamped(self):
        negative = assess_risk(hybrid_result(-0.5))
        above_maximum = assess_risk(hybrid_result(1.5))

        self.assertEqual(negative["risk_score"], 0)
        self.assertEqual(negative["risk_level"], "Low")
        self.assertEqual(above_maximum["risk_score"], 100)
        self.assertEqual(above_maximum["risk_level"], "Critical")

    def test_result_preserves_components_and_explanations(self):
        result = assess_risk(hybrid_result(0.72))

        self.assertEqual(result["risk_score"], 72)
        self.assertEqual(result["risk_level"], "High")
        self.assertEqual(result["components"]["rule_score"], 40)
        self.assertEqual(result["components"]["ml_probability"], 0.8)
        self.assertEqual(result["explainability"]["matched_rules"], ["R001"])
        self.assertTrue(result["reasons"])

    def test_invalid_hybrid_structure_is_rejected(self):
        with self.assertRaises(ValueError):
            assess_risk({})

    def test_flask_displays_risk_assessment(self):
        import tempfile
        from pathlib import Path
        from app import create_app

        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "risk.sqlite3"
            app = create_app(
                {
                    "TESTING": True,
                    "DATABASE_PATH": str(database_path),
                }
            )
            response = app.test_client().post(
                "/",
                data={
                    "username": "student_01",
                    "search_query": "security",
                    "comment": '<img src="javascript:demo" onerror="run()">',
                },
            )

            self.assertEqual(response.status_code, 200)
            self.assertIn(b"RISK ASSESSMENT", response.data)
            self.assertIn(b"RISK SCORE", response.data)
            self.assertIn(b"Risk assessment reasons", response.data)
            self.assertIn(b"HYBRID SIGNAL", response.data)


if __name__ == "__main__":
    unittest.main()

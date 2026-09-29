import unittest

from app import create_app
from app.response import assess_action


def risk_result(level: str, score: float) -> dict:
    return {
        "risk_level": level,
        "risk_score": score,
        "components": {},
        "reasons": ["test reason"],
        "explainability": {},
    }


class ActionEngineTests(unittest.TestCase):
    def test_policy_maps_each_risk_level_to_expected_action(self):
        expected = {
            "Low": "allow",
            "Medium": "flag",
            "High": "block",
            "Critical": "block_and_alert",
        }
        scores = {"Low": 10, "Medium": 30, "High": 60, "Critical": 80}
        for level, action in expected.items():
            with self.subTest(level=level):
                result = assess_action(risk_result(level, scores[level]))
                self.assertEqual(result["action"], action)
                self.assertEqual(result["risk_level"], level)
                self.assertIn("action_message", result)
                self.assertIn("reason", result)

    def test_blocking_actions_are_marked_without_external_side_effects(self):
        high = assess_action(risk_result("High", 72))
        critical = assess_action(risk_result("Critical", 88))

        self.assertTrue(high["blocked"])
        self.assertFalse(high["alert_required"])
        self.assertTrue(critical["blocked"])
        self.assertTrue(critical["alert_required"])

    def test_allow_and_flag_continue_safe_flow(self):
        self.assertFalse(assess_action(risk_result("Low", 0))["blocked"])
        self.assertFalse(assess_action(risk_result("Medium", 30))["blocked"])

    def test_invalid_risk_level_is_rejected(self):
        with self.assertRaises(ValueError):
            assess_action(risk_result("Unknown", 50))

    def test_malformed_risk_result_is_rejected(self):
        with self.assertRaises(ValueError):
            assess_action({})
        with self.assertRaises(ValueError):
            assess_action(risk_result("High", 101))
        with self.assertRaises(ValueError):
            assess_action(risk_result("High", -1))

    def test_inconsistent_score_and_risk_level_are_rejected(self):
        with self.assertRaises(ValueError):
            assess_action(risk_result("High", 30))

    def test_flask_blocks_high_risk_content_without_displaying_submitted_text(self):
        response = create_app().test_client().post(
            "/",
            data={
                "username": "student_01",
                "search_query": "security",
                "comment": '<img src="javascript:demo" onerror="run()">',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"RESPONSE ACTION", response.data)
        self.assertIn(b"block", response.data)
        self.assertIn(b"rejected it", response.data)
        self.assertNotIn(b"&lt;img", response.data)
        self.assertNotIn(b"<img src=", response.data)

    def test_security_headers_are_present(self):
        response = create_app({"TESTING": True}).test_client().get("/")

        self.assertIn(b"default-src 'self'", response.headers["Content-Security-Policy"].encode())
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")


if __name__ == "__main__":
    unittest.main()

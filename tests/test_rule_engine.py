import unittest

from app.detector import detect_text


class RuleEngineTests(unittest.TestCase):
    def test_benign_text_has_no_matches(self):
        result = detect_text("Please share your feedback about the search page.")

        self.assertFalse(result["is_suspicious"])
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["matched_rules"], [])

    def test_benign_unusual_characters_do_not_match_by_themselves(self):
        result = detect_text("Budget: $10 < $20 & status = ready; email@example.com")

        self.assertFalse(result["is_suspicious"])
        self.assertEqual(result["score"], 0)

    def test_multiple_suspicious_categories_are_explained(self):
        result = detect_text(
            '<img src="javascript:demo" onerror="run()">'
        )

        self.assertTrue(result["is_suspicious"])
        self.assertIn("R001", result["matched_rules"])
        self.assertIn("R003", result["matched_rules"])
        self.assertIn("R004", result["matched_rules"])
        self.assertIn("R006", result["matched_rules"])
        self.assertGreater(result["score"], 50)

    def test_empty_input_is_safe_and_not_suspicious(self):
        result = detect_text("")

        self.assertFalse(result["is_suspicious"])
        self.assertEqual(result["score"], 0)

    def test_long_input_is_bounded_without_failing(self):
        result = detect_text("ordinary text " * 2_000)

        self.assertFalse(result["is_suspicious"])
        self.assertEqual(result["score"], 0)

    def test_mixed_case_constructs_are_detected(self):
        result = detect_text("<ScRiPt>demo()</ScRiPt>")

        self.assertTrue(result["is_suspicious"])
        self.assertIn("R001", result["matched_rules"])
        self.assertIn("R002", result["matched_rules"])

    def test_encoded_construct_is_normalized_for_detection(self):
        result = detect_text("%3Cscript%3Edemo()%3C/script%3E")

        self.assertTrue(result["is_suspicious"])
        self.assertIn("R005", result["matched_rules"])
        self.assertIn("R002", result["matched_rules"])


if __name__ == "__main__":
    unittest.main()

import unittest

from app import create_app


class Phase3SecurityTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_homepage_loads(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"User input is treated as untrusted data.", response.data)

    def test_valid_input_is_received_and_special_characters_are_escaped(self):
        response = self.client.post(
            "/",
            data={
                "username": "student_01",
                "search_query": "HTML <tags>",
                "comment": "feedback & notes",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Input received and analyzed", response.data)
        self.assertIn(b"HTML &lt;tags&gt;", response.data)
        self.assertIn(b"feedback &amp; notes", response.data)
        self.assertNotIn(b"<tags>", response.data)
        self.assertNotIn(b"<script>alert('test')</script>", response.data)

    def test_valid_input_shows_rule_based_detection_result(self):
        response = self.client.post(
            "/",
            data={
                "username": "student_01",
                "search_query": "security",
                "comment": '<img src="javascript:demo" onerror="run()">',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"RULE-BASED ANALYSIS", response.data)
        self.assertIn(b"Suspicious characteristics detected", response.data)
        self.assertIn(b"R004", response.data)

    def test_missing_required_input_is_rejected(self):
        response = self.client.post(
            "/",
            data={
                "username": "",
                "search_query": "valid search",
                "comment": "valid comment",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"This field is required.", response.data)
        self.assertNotIn(b"Input received", response.data)

    def test_invalid_username_format_is_rejected(self):
        response = self.client.post(
            "/",
            data={
                "username": "student name",
                "search_query": "valid search",
                "comment": "valid comment",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Use only letters, numbers, underscores, or hyphens.", response.data)

    def test_oversized_comment_is_rejected(self):
        response = self.client.post(
            "/",
            data={
                "username": "student_01",
                "search_query": "valid search",
                "comment": "x" * 1001,
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"This field must be 1000 characters or fewer.", response.data)


if __name__ == "__main__":
    unittest.main()

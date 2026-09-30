import tempfile
import unittest
from base64 import b64encode
from pathlib import Path

from app import create_app
from app.database.db import create_security_event, initialize_database


def event(
    risk_level: str,
    score: float,
    action: str,
    input_text: str = "safe stored text",
) -> dict:
    return {
        "input_text": input_text,
        "rule_score": score,
        "ml_probability": score / 100,
        "ml_prediction": "xss" if risk_level in {"High", "Critical"} else "benign",
        "hybrid_signal": score / 100,
        "risk_score": score,
        "risk_level": risk_level,
        "action": action,
        "detector_agreement": "both_benign",
        "matched_rules": ["R001"] if risk_level != "Low" else [],
        "reasons": ["stored test reason"],
    }


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "dashboard.sqlite3"
        initialize_database(self.database_path)
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE_PATH": str(self.database_path),
                "DASHBOARD_USERNAME": "test-admin",
                "DASHBOARD_PASSWORD": "test-password",
            }
        )
        self.client = self.app.test_client()
        credentials = b64encode(b"test-admin:test-password").decode("ascii")
        self.dashboard_headers = {"Authorization": f"Basic {credentials}"}

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_empty_dashboard_loads_without_fake_data(self):
        response = self.client.get("/dashboard", headers=self.dashboard_headers)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No security events recorded yet.", response.data)
        self.assertIn(b"0", response.data)

    def test_dashboard_statistics_use_actual_records(self):
        create_security_event(event("Low", 10, "allow"), self.database_path)
        create_security_event(event("Critical", 90, "block_and_alert"), self.database_path)

        response = self.client.get("/dashboard", headers=self.dashboard_headers)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"TOTAL EVENTS", response.data)
        self.assertIn(b"BLOCKED", response.data)
        self.assertIn(b"EVENT REVIEW", response.data)
        self.assertIn(b"#2", response.data)
        self.assertIn(b"#1", response.data)

    def test_risk_and_action_filters_are_applied(self):
        create_security_event(event("Low", 10, "allow"), self.database_path)
        create_security_event(event("Critical", 90, "block_and_alert"), self.database_path)

        risk_response = self.client.get(
            "/dashboard?risk_level=Critical", headers=self.dashboard_headers
        )
        action_response = self.client.get(
            "/dashboard?action=allow", headers=self.dashboard_headers
        )

        self.assertIn(b"#2", risk_response.data)
        self.assertNotIn(b"#1", risk_response.data)
        self.assertIn(b"#1", action_response.data)
        self.assertNotIn(b"#2", action_response.data)

    def test_search_filter_is_applied(self):
        create_security_event(
            event("Low", 10, "allow", input_text="unique dashboard phrase"),
            self.database_path,
        )
        create_security_event(event("Critical", 90, "block_and_alert"), self.database_path)

        response = self.client.get(
            "/dashboard?search=unique+dashboard",
            headers=self.dashboard_headers,
        )

        self.assertIn(b"#1", response.data)
        self.assertNotIn(b"#2", response.data)

    def test_filter_values_are_treated_as_data(self):
        response = self.client.get(
            "/dashboard?risk_level=%27%20OR%201%3D1%20--&search=%27%20OR%201%3D1%20--",
            headers=self.dashboard_headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No matching security events.", response.data)

    def test_event_detail_is_safe_and_complete(self):
        created = create_security_event(
            event("High", 70, "block", input_text="<script>alert('stored')</script>"),
            self.database_path,
        )

        response = self.client.get(
            f"/dashboard/event/{created['id']}",
            headers=self.dashboard_headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Event #1", response.data)
        self.assertIn(b"Matched Rules", response.data)
        self.assertIn(b"&lt;script&gt;alert(&#39;stored&#39;)&lt;/script&gt;", response.data)
        self.assertNotIn(b"<script>alert('stored')</script>", response.data)

    def test_invalid_event_id_returns_404(self):
        response = self.client.get(
            "/dashboard/event/999",
            headers=self.dashboard_headers,
        )

        self.assertEqual(response.status_code, 404)
        self.assertIn(b"Event not found", response.data)

    def test_dashboard_requires_authentication(self):
        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 401)
        self.assertIn("WWW-Authenticate", response.headers)

    def test_dashboard_is_unavailable_without_configured_password(self):
        app = create_app(
            {
                "TESTING": True,
                "DATABASE_PATH": str(self.database_path),
                "DASHBOARD_PASSWORD": None,
            }
        )

        response = app.test_client().get("/dashboard")

        self.assertEqual(response.status_code, 503)
        self.assertIn(b"Dashboard access is not configured", response.data)

    def test_dashboard_shows_applications_and_safe_operational_context(self):
        create_security_event(event("High", 70, "block"), self.database_path)

        response = self.client.get("/dashboard", headers=self.dashboard_headers)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Registered apps", response.data)
        self.assertIn(b"Legacy Local Application", response.data)
        self.assertIn(b"Observed signals", response.data)
        self.assertIn(b"browser_analysis", response.data)
        self.assertNotIn(b"xsh_", response.data)

    def test_dashboard_handles_optional_event_metadata(self):
        created = event("Medium", 40, "flag")
        created["application_id"] = 1
        create_security_event(created, self.database_path)

        response = self.client.get("/dashboard", headers=self.dashboard_headers)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"browser_analysis", response.data)


if __name__ == "__main__":
    unittest.main()

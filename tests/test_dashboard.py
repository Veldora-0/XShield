import tempfile
import unittest
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
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_empty_dashboard_loads_without_fake_data(self):
        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No security events recorded yet.", response.data)
        self.assertIn(b"0", response.data)

    def test_dashboard_statistics_use_actual_records(self):
        create_security_event(event("Low", 10, "allow"), self.database_path)
        create_security_event(event("Critical", 90, "block_and_alert"), self.database_path)

        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"TOTAL EVENTS", response.data)
        self.assertIn(b"BLOCKED", response.data)
        self.assertIn(b"EVENT REVIEW", response.data)
        self.assertIn(b"#2", response.data)
        self.assertIn(b"#1", response.data)

    def test_risk_and_action_filters_are_applied(self):
        create_security_event(event("Low", 10, "allow"), self.database_path)
        create_security_event(event("Critical", 90, "block_and_alert"), self.database_path)

        risk_response = self.client.get("/dashboard?risk_level=Critical")
        action_response = self.client.get("/dashboard?action=allow")

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

        response = self.client.get("/dashboard?search=unique+dashboard")

        self.assertIn(b"#1", response.data)
        self.assertNotIn(b"#2", response.data)

    def test_filter_values_are_treated_as_data(self):
        response = self.client.get(
            "/dashboard?risk_level=%27%20OR%201%3D1%20--&search=%27%20OR%201%3D1%20--"
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No matching security events.", response.data)

    def test_event_detail_is_safe_and_complete(self):
        created = create_security_event(
            event("High", 70, "block", input_text="<script>alert('stored')</script>"),
            self.database_path,
        )

        response = self.client.get(f"/dashboard/event/{created['id']}")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Event #1", response.data)
        self.assertIn(b"Matched Rules", response.data)
        self.assertIn(b"&lt;script&gt;alert(&#39;stored&#39;)&lt;/script&gt;", response.data)
        self.assertNotIn(b"<script>alert('stored')</script>", response.data)

    def test_invalid_event_id_returns_404(self):
        response = self.client.get("/dashboard/event/999")

        self.assertEqual(response.status_code, 404)
        self.assertIn(b"Event not found", response.data)

    def test_console_routes_are_accessible_without_authentication(self):
        created = create_security_event(
            event("High", 70, "block", input_text="<script>alert('test')</script>"),
            self.database_path,
        )
        endpoints = [
            "/dashboard",
            "/dashboard/events",
            "/dashboard/incidents",
            "/dashboard/behavior",
            "/dashboard/applications",
            f"/dashboard/event/{created['id']}",
        ]
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                self.assertEqual(response.status_code, 200)

    def test_console_operates_without_dashboard_auth_environment_variables(self):
        app = create_app(
            {
                "TESTING": True,
                "DATABASE_PATH": str(self.database_path),
            }
        )
        response = app.test_client().get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("WWW-Authenticate", response.headers)

    def test_api_ingestion_authentication_remains_strictly_enforced(self):
        # 1. Missing API key returns 401
        payload = {
            "input_fields": {"comment": "test comment"},
        }
        res_no_key = self.client.post(
            "/api/v1/events",
            json=payload,
        )
        self.assertEqual(res_no_key.status_code, 401)
        data = res_no_key.get_json()
        self.assertEqual(data["accepted"], False)
        self.assertEqual(data["error"], "API key authentication required.")

        # 2. Invalid API key returns 401
        res_bad_key = self.client.post(
            "/api/v1/events",
            json=payload,
            headers={"X-API-Key": "xsh_invalid_key_12345"},
        )
        self.assertEqual(res_bad_key.status_code, 401)
        data = res_bad_key.get_json()
        self.assertEqual(data["accepted"], False)
        self.assertEqual(data["error"], "API key authentication required.")

        # 3. Valid active API key returns 201
        from app.database import create_application
        from app.services.api_keys import create_api_key
        app_record = create_application(
            "test-service", "Test API Service", database_path=self.database_path
        )
        key_record = create_api_key(
            app_record["id"], database_path=self.database_path
        )
        res_valid = self.client.post(
            "/api/v1/events",
            json=payload,
            headers={"X-API-Key": key_record["api_key"]},
        )
        self.assertEqual(res_valid.status_code, 201)
        valid_data = res_valid.get_json()
        self.assertEqual(valid_data["status"], "accepted")
        self.assertEqual(valid_data["accepted"], True)

    def test_dashboard_shows_applications_and_safe_operational_context(self):
        create_security_event(event("High", 70, "block"), self.database_path)

        response = self.client.get("/dashboard")

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

        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"browser_analysis", response.data)


if __name__ == "__main__":
    unittest.main()

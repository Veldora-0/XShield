import tempfile
import unittest
from base64 import b64encode
from pathlib import Path

from app import create_app
from app.database import count_events


class Phase13PipelineTests(unittest.TestCase):
    def test_submission_is_logged_and_visible_on_dashboard(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "pipeline.sqlite3"
            app = create_app(
                {
                    "TESTING": True,
                    "DATABASE_PATH": str(database_path),
                    "DASHBOARD_USERNAME": "test-admin",
                    "DASHBOARD_PASSWORD": "test-password",
                }
            )
            client = app.test_client()
            response = client.post(
                "/",
                data={
                    "username": "student_01",
                    "search_query": "security",
                    "comment": '<img src="javascript:demo" onerror="run()">',
                },
            )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(count_events(database_path), 1)
            credentials = b64encode(b"test-admin:test-password").decode("ascii")
            dashboard = client.get(
                "/dashboard",
                headers={"Authorization": f"Basic {credentials}"},
            )
            self.assertEqual(dashboard.status_code, 200)
            self.assertIn(b"CRITICAL", dashboard.data)
            self.assertIn(b"block_and_alert", dashboard.data)


if __name__ == "__main__":
    unittest.main()

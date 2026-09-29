import tempfile
import unittest
import sqlite3
from pathlib import Path

from app import create_app
from app.database import (
    count_events,
    create_application,
    get_application_by_slug,
    get_event_by_id,
    get_event_counts_by_risk,
    get_recent_events,
    initialize_database,
    list_applications,
)


def sample_event() -> dict:
    return {
        "input_text": "offline test input",
        "rule_score": 40,
        "ml_probability": 0.8,
        "ml_prediction": "xss",
        "hybrid_signal": 0.6,
        "risk_score": 60,
        "risk_level": "High",
        "action": "block",
        "detector_agreement": "both_suspicious",
        "matched_rules": ["R001", "R006"],
        "reasons": ["markup", "multiple indicators"],
    }


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "test.sqlite3"
        initialize_database(self.database_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_initialization_and_empty_queries(self):
        self.assertEqual(count_events(self.database_path), 0)
        self.assertEqual(get_recent_events(database_path=self.database_path), [])
        self.assertEqual(get_event_counts_by_risk(self.database_path), {})
        legacy = get_application_by_slug("legacy-local", self.database_path)
        self.assertIsNotNone(legacy)
        self.assertEqual(len(list_applications(self.database_path)), 1)

    def test_event_persistence_and_json_round_trip(self):
        from app.database.db import create_security_event

        created = create_security_event(sample_event(), self.database_path)
        event = get_event_by_id(created["id"], self.database_path)

        self.assertIsNotNone(event)
        self.assertEqual(event["matched_rules"], ["R001", "R006"])
        self.assertEqual(event["reasons"], ["markup", "multiple indicators"])
        self.assertEqual(event["risk_level"], "High")
        self.assertTrue(event["timestamp"])
        self.assertEqual(count_events(self.database_path), 1)
        self.assertEqual(event["application_id"], 1)

    def test_recent_events_and_risk_counts(self):
        from app.database.db import create_security_event

        create_security_event(sample_event(), self.database_path)
        second = sample_event()
        second.update({"risk_level": "Critical", "risk_score": 90})
        create_security_event(second, self.database_path)

        recent = get_recent_events(limit=1, database_path=self.database_path)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["risk_level"], "Critical")
        self.assertEqual(
            get_event_counts_by_risk(self.database_path),
            {"Critical": 1, "High": 1},
        )

    def test_invalid_recent_limit_is_rejected(self):
        with self.assertRaises(ValueError):
            get_recent_events(limit=0, database_path=self.database_path)

    def test_flask_request_persists_a_real_event_in_isolated_database(self):
        app = create_app(
            {
                "TESTING": True,
                "DATABASE_PATH": str(self.database_path),
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
        self.assertIn(b"Event stored", response.data)
        self.assertEqual(count_events(self.database_path), 1)
        event = get_recent_events(database_path=self.database_path)[0]
        self.assertEqual(event["action"], "block_and_alert")
        self.assertEqual(event["risk_level"], "Critical")
        self.assertIn("R001", event["matched_rules"])

    def test_application_registry_supports_multiple_applications(self):
        created = create_application(
            "demo-site",
            "Demo Site",
            "Local integration test application.",
            self.database_path,
        )

        self.assertEqual(created["slug"], "demo-site")
        self.assertEqual(
            get_application_by_slug("demo-site", self.database_path)["id"],
            created["id"],
        )
        self.assertEqual(len(list_applications(self.database_path)), 2)

    def test_existing_database_is_upgraded_and_events_are_backfilled(self):
        legacy_path = Path(self.temp_dir.name) / "legacy.sqlite3"
        connection = sqlite3.connect(legacy_path)
        try:
            connection.execute(
                """
                CREATE TABLE security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    input_text TEXT NOT NULL,
                    rule_score REAL NOT NULL,
                    ml_probability REAL NOT NULL,
                    ml_prediction TEXT NOT NULL,
                    hybrid_signal REAL NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    action TEXT NOT NULL,
                    detector_agreement TEXT NOT NULL,
                    matched_rules TEXT NOT NULL,
                    reasons TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                INSERT INTO security_events VALUES
                    (1, '2026-01-01T00:00:00+00:00', 'legacy event',
                     0, 0.1, 'benign', 0.05, 5, 'Low', 'allow',
                     'both_benign', '[]', '[]')
                """
            )
            connection.commit()
        finally:
            connection.close()

        initialize_database(legacy_path)
        event = get_event_by_id(1, legacy_path)
        self.assertEqual(event["input_text"], "legacy event")
        self.assertEqual(event["application_id"], 1)

    def test_initialization_is_idempotent(self):
        initialize_database(self.database_path)
        initialize_database(self.database_path)

        self.assertEqual(len(list_applications(self.database_path)), 1)
        self.assertEqual(count_events(self.database_path), 0)


if __name__ == "__main__":
    unittest.main()

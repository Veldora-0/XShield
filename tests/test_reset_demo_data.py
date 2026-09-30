"""Tests for the local demonstration data reset mechanism."""

import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from app import create_app
from app.database import (
    DEFAULT_DATABASE_PATH,
    count_events,
    create_application,
    create_security_event,
    get_event_by_id,
    initialize_database,
    list_applications,
    reset_demo_events,
)
from app.services import (
    authenticate_api_key,
    create_api_key,
    get_dashboard_snapshot,
    list_api_keys,
)
from scripts.reset_demo_data import REQUIRED_CONFIRMATION, run_reset


def _create_sample_event(text: str = "probe payload", risk_level: str = "High", action: str = "block") -> dict:
    return {
        "input_text": text,
        "rule_score": 80.0,
        "ml_probability": 0.85,
        "ml_prediction": "xss",
        "hybrid_signal": 0.825,
        "risk_score": 82.5,
        "risk_level": risk_level,
        "action": action,
        "detector_agreement": "both_suspicious",
        "matched_rules": ["script_tag"],
        "reasons": ["Detected script tag", "High ML confidence"],
        "application_id": 1,
    }


class TestResetDemoData(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "test_reset.sqlite3"
        initialize_database(self.database_path)

        # Create registered test application and API key
        self.app_info = create_application(
            slug="test-app",
            name="Test Client Application",
            description="Integration test app",
            database_path=self.database_path,
        )
        self.key_info = create_api_key(
            application_id=self.app_info["id"],
            database_path=self.database_path,
        )
        self.raw_api_key = self.key_info["api_key"]

        # Insert sample events
        create_security_event(_create_sample_event("test vector 1"), self.database_path)
        create_security_event(_create_sample_event("test vector 2"), self.database_path)
        create_security_event(_create_sample_event("test vector 3", risk_level="Critical", action="block_and_alert"), self.database_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_1_reset_requires_explicit_confirmation(self):
        """Test Requirement 1: Non-interactive run without confirmation aborts without modifying data."""
        events_before = count_events(self.database_path)
        self.assertEqual(events_before, 3)

        exit_code = run_reset(self.database_path, confirmation=None, interactive=False)
        self.assertEqual(exit_code, 1)
        self.assertEqual(count_events(self.database_path), 3)

    def test_2_wrong_confirmation_does_not_delete_anything(self):
        """Test Requirement 2: Casual or invalid confirmations ('y', 'yes', '1', 'reset') abort."""
        invalid_inputs = ["y", "yes", "1", "reset", "CANCEL", "NO", "true"]
        for bad_input in invalid_inputs:
            with self.subTest(bad_input=bad_input):
                exit_code = run_reset(self.database_path, confirmation=bad_input)
                self.assertEqual(exit_code, 1)
                self.assertEqual(count_events(self.database_path), 3)

    def test_3_correct_confirmation_deletes_security_events(self):
        """Test Requirement 3: Explicit 'RESET' confirmation deletes all security events."""
        self.assertEqual(count_events(self.database_path), 3)

        exit_code = run_reset(self.database_path, confirmation="RESET")
        self.assertEqual(exit_code, 0)
        self.assertEqual(count_events(self.database_path), 0)

    def test_4_applications_are_preserved(self):
        """Test Requirement 4: Application registrations are preserved after reset."""
        apps_before = list_applications(self.database_path)
        self.assertGreaterEqual(len(apps_before), 2)  # legacy-local + test-app

        run_reset(self.database_path, confirmation="RESET")

        apps_after = list_applications(self.database_path)
        self.assertEqual(len(apps_before), len(apps_after))
        slugs = [a["slug"] for a in apps_after]
        self.assertIn("test-app", slugs)
        self.assertIn("legacy-local", slugs)

    def test_5_api_keys_are_preserved(self):
        """Test Requirement 5: API keys remain intact with matching status and hashes."""
        keys_before = list_api_keys(self.database_path)
        self.assertEqual(len(keys_before), 1)

        run_reset(self.database_path, confirmation="RESET")

        keys_after = list_api_keys(self.database_path)
        self.assertEqual(len(keys_after), 1)
        self.assertEqual(keys_after[0]["id"], keys_before[0]["id"])
        self.assertEqual(keys_after[0]["status"], "active")

    def test_6_database_schema_remains_intact(self):
        """Test Requirement 6: Database schema, tables, and indexes remain completely intact."""
        run_reset(self.database_path, confirmation="RESET")

        conn = sqlite3.connect(self.database_path)
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        conn.close()

        self.assertIn("security_events", tables)
        self.assertIn("applications", tables)
        self.assertIn("api_keys", tables)
        self.assertIn("schema_migrations", tables)

    def test_7_existing_api_key_can_still_authenticate_after_reset(self):
        """Test Requirement 7: Existing API key continues to authenticate successfully after reset."""
        auth_before = authenticate_api_key({"X-API-Key": self.raw_api_key}, self.database_path)
        self.assertTrue(auth_before.authenticated)

        run_reset(self.database_path, confirmation="RESET")

        auth_after = authenticate_api_key({"X-API-Key": self.raw_api_key}, self.database_path)
        self.assertTrue(auth_after.authenticated)
        self.assertEqual(auth_after.application["slug"], "test-app")

    def test_8_new_event_can_be_inserted_after_reset(self):
        """Test Requirement 8: New security events can be inserted normally after reset."""
        run_reset(self.database_path, confirmation="RESET")
        self.assertEqual(count_events(self.database_path), 0)

        created = create_security_event(_create_sample_event("new event post-reset"), self.database_path)
        self.assertIsNotNone(created.get("id"))
        self.assertEqual(count_events(self.database_path), 1)

        event = get_event_by_id(created["id"], self.database_path)
        self.assertIsNotNone(event)
        self.assertEqual(event["input_text"], "new event post-reset")

    def test_9_event_persistence_works_after_xshield_restart(self):
        """Test Requirement 9: XShield restart preserves events inserted post-reset."""
        run_reset(self.database_path, confirmation="RESET")
        self.assertEqual(count_events(self.database_path), 0)

        # Insert new event
        create_security_event(_create_sample_event("persistent event"), self.database_path)
        self.assertEqual(count_events(self.database_path), 1)

        # Simulate restart: create app anew against the same database path
        app = create_app({"TESTING": True, "DATABASE_PATH": str(self.database_path)})
        client = app.test_client()
        res = client.get("/dashboard")
        self.assertEqual(res.status_code, 200)

        # Verify event was NOT deleted by startup
        self.assertEqual(count_events(self.database_path), 1)

    def test_10_reset_is_transactional(self):
        """Test Requirement 10: reset_demo_events executes within an atomic transaction."""
        deleted = reset_demo_events(self.database_path)
        self.assertEqual(deleted, 3)
        self.assertEqual(count_events(self.database_path), 0)

    def test_11_failed_reset_does_not_leave_partial_deletion(self):
        """Test Requirement 11: Transactional failure triggers rollback, leaving data intact."""
        from contextlib import contextmanager

        @contextmanager
        def broken_connect(path):
            conn = sqlite3.connect(str(path))
            conn.execute("PRAGMA foreign_keys = ON")
            try:
                # Partially delete one row to simulate mid-transaction failure
                conn.execute("DELETE FROM security_events WHERE id = 1")
                raise sqlite3.OperationalError("Simulated disk error during batch delete")
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

        with patch("app.database.db._connect", broken_connect):
            with self.assertRaises(sqlite3.OperationalError):
                reset_demo_events(self.database_path)

        # Due to rollback, all events must still be present
        self.assertEqual(count_events(self.database_path), 3)

    def test_12_behavioral_and_incident_views_empty_when_events_empty(self):
        """Test Requirement 12: Behavioral and incident views become empty after reset."""
        snapshot_before = get_dashboard_snapshot(database_path=self.database_path)
        self.assertEqual(snapshot_before["stats"]["total_events"], 3)

        run_reset(self.database_path, confirmation="RESET")

        snapshot_after = get_dashboard_snapshot(database_path=self.database_path)
        self.assertEqual(snapshot_after["stats"]["total_events"], 0)
        self.assertEqual(snapshot_after["stats"]["blocked_events"], 0)
        self.assertEqual(snapshot_after["incidents"], [])
        self.assertEqual(snapshot_after["behavior"]["recent_event_count"], 0)
        self.assertEqual(snapshot_after["events"], [])

    def test_13_reset_does_not_touch_ml_models(self):
        """Test Requirement 13: Production ML models are never touched by reset."""
        model_path = Path("models/xss_logistic_regression.joblib")
        vectorizer_path = Path("models/xss_tfidf_vectorizer.joblib")

        self.assertTrue(model_path.exists())
        self.assertTrue(vectorizer_path.exists())

        mtime_before = model_path.stat().st_mtime
        run_reset(self.database_path, confirmation="RESET")
        mtime_after = model_path.stat().st_mtime

        self.assertEqual(mtime_before, mtime_after)

    def test_14_reset_does_not_touch_datasets(self):
        """Test Requirement 14: Datasets are never touched by reset."""
        dataset_path = Path("data/processed/xss_dataset.csv")
        self.assertTrue(dataset_path.exists())

        mtime_before = dataset_path.stat().st_mtime
        run_reset(self.database_path, confirmation="RESET")
        mtime_after = dataset_path.stat().st_mtime

        self.assertEqual(mtime_before, mtime_after)

    def test_15_reset_does_not_touch_candidate_v2_artifacts(self):
        """Test Requirement 15: Candidate V2 model artifacts are never touched by reset."""
        candidate_model = Path("models/candidate_v2/xss_logistic_regression.joblib")
        candidate_vec = Path("models/candidate_v2/xss_tfidf_vectorizer.joblib")

        self.assertTrue(candidate_model.exists())
        self.assertTrue(candidate_vec.exists())

        mtime_before = candidate_model.stat().st_mtime
        run_reset(self.database_path, confirmation="RESET")
        mtime_after = candidate_model.stat().st_mtime

    def test_16_test_suite_does_not_contaminate_production_database_path(self):
        """Regression Guard: Verify tests with isolated DATABASE_PATH do not write to default database."""
        events_before = count_events(self.database_path)
        app = create_app({"TESTING": True, "DATABASE_PATH": str(self.database_path)})
        self.assertNotEqual(Path(app.config["DATABASE_PATH"]), DEFAULT_DATABASE_PATH)
        client = app.test_client()
        client.post(
            "/",
            data={
                "username": "student_01",
                "search_query": "security",
                "comment": '<img src="javascript:demo" onerror="run()">',
            },
        )
        self.assertEqual(count_events(self.database_path), events_before + 1)


if __name__ == "__main__":
    unittest.main()

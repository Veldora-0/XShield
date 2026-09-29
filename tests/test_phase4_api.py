import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import create_app
from app.database import (
    count_events,
    create_application,
    create_security_event,
    get_event_by_id,
    initialize_database,
)
from app.services.api_keys import create_api_key, revoke_api_key


def browser_event(text="historical event"):
    return {
        "input_text": text,
        "rule_score": 0,
        "ml_probability": 0,
        "ml_prediction": "benign",
        "hybrid_signal": 0,
        "risk_score": 0,
        "risk_level": "Low",
        "action": "allow",
        "detector_agreement": "both_benign",
        "matched_rules": [],
        "reasons": [],
    }


class Phase4ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "api.sqlite3"
        initialize_database(self.database_path)
        self.application = create_application(
            "integration-one", "Integration One", database_path=self.database_path
        )
        self.other_application = create_application(
            "integration-two", "Integration Two", database_path=self.database_path
        )
        self.key = create_api_key(self.application["id"], self.database_path)["api_key"]
        self.other_key = create_api_key(
            self.other_application["id"], self.database_path
        )["api_key"]
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE_PATH": str(self.database_path),
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def payload(self, **updates):
        value = {
            "event_type": "request_observation",
            "endpoint": "/search",
            "method": "post",
            "input_fields": {"query": "<img src=x>"},
            "request_id": "req-123",
            "metadata": {
                "client_ip": {"value": "127.0.0.1", "trust": "observed"}
            },
            "retention_mode": "truncated",
        }
        value.update(updates)
        return value

    def post(self, payload=None, key="default", **kwargs):
        headers = {"Content-Type": "application/json"}
        if key == "default":
            key = self.key
        if key is not None:
            headers["X-API-Key"] = key
        return self.client.post(
            "/api/v1/events",
            data=json.dumps(self.payload() if payload is None else payload),
            headers=headers,
            **kwargs,
        )

    def test_missing_invalid_revoked_expired_and_revoked_application_keys(self):
        self.assertEqual(self.post(key=None).status_code, 401)
        self.assertEqual(self.post(key="xsh_invalid").status_code, 401)

        revoke_api_key(
            next(
                item["id"]
                for item in self._keys()
                if item["application_id"] == self.application["id"]
            ),
            self.database_path,
        )
        self.assertEqual(self.post(key=self.key).status_code, 403)

        expired = create_api_key(
            self.application["id"],
            self.database_path,
            expires_at=(
                datetime.now(timezone.utc) - timedelta(minutes=1)
            ).isoformat(),
        )["api_key"]
        self.assertEqual(self.post(key=expired).status_code, 403)

        self.application = create_application(
            "third-application", "Third", database_path=self.database_path
        )
        application_key = create_api_key(
            self.application["id"], self.database_path
        )["api_key"]
        from app.database import set_application_status

        set_application_status(self.application["id"], "revoked", self.database_path)
        self.assertEqual(self.post(key=application_key).status_code, 403)

    def _keys(self):
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            return [dict(row) for row in connection.execute("SELECT * FROM api_keys")]
        finally:
            connection.close()

    def test_valid_event_returns_stable_response_and_persists_association(self):
        response = self.post()

        self.assertEqual(response.status_code, 201)
        body = response.get_json()
        self.assertEqual(
            set(body), {"accepted", "event_id", "application", "status"}
        )
        self.assertTrue(body["accepted"])
        self.assertEqual(body["application"], "integration-one")
        self.assertEqual(body["status"], "accepted")

        stored = get_event_by_id(body["event_id"], self.database_path)
        self.assertEqual(stored["application_id"], self.application["id"])
        self.assertEqual(stored["event_type"], "request_observation")
        self.assertEqual(stored["source"], "api")
        self.assertEqual(stored["http_method"], "POST")
        self.assertEqual(stored["input_fields"]["query"], "<img src=x>")
        self.assertEqual(stored["metadata"]["client_ip"]["trust"], "observed")

    def test_client_cannot_override_application_association(self):
        payload = self.payload(
            application_id=self.other_application["id"],
        )
        response = self.post(payload)

        self.assertEqual(response.status_code, 422)
        self.assertEqual(count_events(self.database_path), 0)

    def test_two_applications_are_isolated(self):
        first = self.post(key=self.key)
        second = self.post(key=self.other_key)

        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 201)
        first_event = get_event_by_id(first.get_json()["event_id"], self.database_path)
        second_event = get_event_by_id(second.get_json()["event_id"], self.database_path)
        self.assertEqual(first_event["application_id"], self.application["id"])
        self.assertEqual(
            second_event["application_id"], self.other_application["id"]
        )

    def test_invalid_json_and_content_type_are_rejected(self):
        response = self.client.post(
            "/api/v1/events",
            data="{not-json}",
            headers={"X-API-Key": self.key, "Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 400)
        response = self.client.post(
            "/api/v1/events",
            data=json.dumps(self.payload()),
            headers={"X-API-Key": self.key, "Content-Type": "text/plain"},
        )
        self.assertEqual(response.status_code, 415)

    def test_payload_bounds_and_supported_structure_are_enforced(self):
        cases = (
            self.payload(input_fields={}),
            self.payload(event_type="unsupported"),
            self.payload(metadata={"a": "not-a-trusted-value"}),
            self.payload(
                metadata={
                    str(index): {"value": "x", "trust": "supplied"}
                    for index in range(33)
                }
            ),
            self.payload(input_fields={"query": "x" * 10001}),
            self.payload(unexpected="value"),
        )
        for payload in cases:
            with self.subTest(payload=payload):
                self.assertEqual(self.post(payload).status_code, 422)

    def test_retention_modes_do_not_store_unbounded_raw_input(self):
        for mode, expected in (
            ("truncated", "x" * 2000),
            ("hash_only", None),
            ("redacted", "[REDACTED]"),
            ("disabled", ""),
        ):
            with self.subTest(mode=mode):
                response = self.post(
                    self.payload(
                        input_fields={"query": "x" * 10000},
                        retention_mode=mode,
                    )
                )
                self.assertEqual(response.status_code, 201)
                stored = get_event_by_id(
                    response.get_json()["event_id"], self.database_path
                )
                if mode == "hash_only":
                    self.assertEqual(len(stored["input_text"]), 64)
                    self.assertNotIn("x", stored["input_text"])
                else:
                    self.assertEqual(stored["input_text"], expected)

    def test_historical_events_remain_and_sql_like_input_is_data(self):
        historical = create_security_event(browser_event(), self.database_path)
        response = self.post(
            self.payload(
                input_fields={"query": "' OR 1=1; DROP TABLE api_keys;--"}
            )
        )

        self.assertEqual(response.status_code, 201)
        self.assertIsNotNone(get_event_by_id(historical["id"], self.database_path))
        self.assertEqual(len(self._keys()), 2)

    def test_unsupported_method_and_health_homepage_remain_available(self):
        response = self.client.get("/api/v1/events")
        self.assertEqual(response.status_code, 405)
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/health").status_code, 200)

    def test_migration_is_repeatedly_safe_and_schema_is_v4(self):
        initialize_database(self.database_path)
        initialize_database(self.database_path)
        connection = sqlite3.connect(self.database_path)
        try:
            version = connection.execute(
                "SELECT MAX(version) FROM schema_migrations"
            ).fetchone()[0]
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(security_events)")
            }
        finally:
            connection.close()
        self.assertEqual(version, 4)
        self.assertIn("metadata", columns)
        self.assertIn("event_type", columns)


if __name__ == "__main__":
    unittest.main()

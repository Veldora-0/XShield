import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from app.database import create_application, get_event_by_id, initialize_database
from app.response import assess_action
from app.risk import assess_risk
from app.services.api_keys import create_api_key
from app.services.analysis import analyze_security_input


class Phase5PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "phase5.sqlite3"
        initialize_database(self.database_path)
        application = create_application(
            "phase5-app", "Phase 5 App", database_path=self.database_path
        )
        self.key = create_api_key(application["id"], self.database_path)["api_key"]
        self.application_id = application["id"]
        self.app = create_app(
            {"TESTING": True, "DATABASE_PATH": str(self.database_path)}
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def payload(self, value="ordinary text", event_type="input_analysis"):
        return {
            "event_type": event_type,
            "endpoint": "/search",
            "method": "POST",
            "input_fields": {"comment": value, "username": "operator"},
            "metadata": {
                "client_ip": {"value": "127.0.0.1", "trust": "observed"}
            },
            "retention_mode": "truncated",
        }

    def post(self, payload):
        return self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            content_type="application/json",
            headers={"X-API-Key": self.key},
        )

    def test_shared_service_invokes_existing_pipeline_layers(self):
        with patch(
            "app.services.analysis.detect_hybrid_fields",
            return_value={
                "rule_result": {
                    "score": 0,
                    "is_suspicious": False,
                    "matched_rules": [],
                    "risk_indicators": [],
                },
                "ml_result": {"probability": 0.1, "prediction": "benign", "label": 0},
                "hybrid": {
                    "rule_score_normalized": 0.0,
                    "ml_score": 0.1,
                    "rule_weight": 0.5,
                    "ml_weight": 0.5,
                    "rule_contribution": 0.0,
                    "ml_contribution": 0.05,
                    "hybrid_signal": 0.05,
                    "agreement": "both_benign",
                },
            },
        ) as hybrid, patch(
                "app.services.analysis.assess_risk",
                wraps=assess_risk,
            ) as risk, patch(
                "app.services.analysis.assess_action",
                wraps=assess_action,
            ) as action:
            result = analyze_security_input({"comment": "ordinary text"})

        hybrid.assert_called_once()
        risk.assert_called_once()
        action.assert_called_once()
        self.assertEqual(result["risk_result"]["risk_level"], "Low")
        self.assertEqual(result["action_result"]["action"], "allow")

    def test_api_event_receives_real_rule_ml_risk_and_action_results(self):
        response = self.post(self.payload('<img src="javascript:demo" onerror="run()">'))

        self.assertEqual(response.status_code, 201)
        event = get_event_by_id(response.get_json()["event_id"], self.database_path)
        self.assertNotEqual(event["ml_prediction"], "not_analyzed")
        self.assertGreater(event["rule_score"], 0)
        self.assertGreater(event["risk_score"], 0)
        self.assertIn(event["action"], {"flag", "block", "block_and_alert"})
        self.assertEqual(event["application_id"], self.application_id)
        self.assertEqual(event["source"], "api")

    def test_both_supported_event_types_use_the_same_analysis_path(self):
        with patch(
            "app.services.event_ingestion.analyze_security_input",
            wraps=analyze_security_input,
        ) as analyze:
            self.assertEqual(self.post(self.payload(event_type="input_analysis")).status_code, 201)
            self.assertEqual(
                self.post(self.payload(event_type="request_observation")).status_code,
                201,
            )
        self.assertEqual(analyze.call_count, 2)

    def test_metadata_is_not_analyzed_as_payload(self):
        response = self.post(
            {
                **self.payload("ordinary text"),
                "metadata": {
                    "payload": {
                        "value": '<script>alert("metadata")</script>',
                        "trust": "supplied",
                    }
                },
            }
        )

        event = get_event_by_id(response.get_json()["event_id"], self.database_path)
        self.assertEqual(event["rule_score"], 0)
        self.assertEqual(event["risk_level"], "Low")
        self.assertEqual(event["action"], "allow")

    def test_client_analysis_results_are_rejected(self):
        response = self.post(
            {
                **self.payload("ordinary text"),
                "risk": "low",
                "action": "allow",
                "is_malicious": False,
            }
        )

        self.assertEqual(response.status_code, 422)

    def test_analysis_failure_returns_controlled_error_without_persisting(self):
        with patch(
            "app.services.event_ingestion.analyze_security_input",
            side_effect=RuntimeError("model unavailable"),
        ):
            response = self.post(self.payload("ordinary text"))

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json(), {
            "accepted": False,
            "error": "Event analysis failed.",
        })
        connection = sqlite3.connect(self.database_path)
        try:
            count = connection.execute(
                "SELECT COUNT(*) FROM security_events WHERE source = 'api'"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(count, 0)

    def test_persistence_failure_returns_controlled_error(self):
        with patch(
            "app.services.event_ingestion.create_ingested_event",
            side_effect=sqlite3.Error("database details"),
        ):
            response = self.post(self.payload("ordinary text"))

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json(), {
            "accepted": False,
            "error": "Event could not be stored.",
        })

    def test_each_api_event_is_analyzed_once(self):
        with patch(
            "app.services.event_ingestion.analyze_security_input",
            wraps=analyze_security_input,
        ) as analyze:
            response = self.post(self.payload("ordinary text"))

        self.assertEqual(response.status_code, 201)
        self.assertEqual(analyze.call_count, 1)

    def test_browser_flow_uses_shared_analysis_service(self):
        with patch(
            "app.routes.analyze_security_input",
            wraps=analyze_security_input,
        ) as analyze:
            response = self.client.post(
                "/",
                data={
                    "username": "operator",
                    "search_query": "ordinary",
                    "comment": "text",
                },
            )

        self.assertEqual(response.status_code, 200)
        analyze.assert_called_once()


if __name__ == "__main__":
    unittest.main()

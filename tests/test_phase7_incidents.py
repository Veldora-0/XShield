import unittest
from datetime import datetime, timedelta, timezone

from app.config import (
    INCIDENT_CORRELATION_WINDOW_SECONDS,
    INCIDENT_MAX_RECENT_EVENTS,
)
from app.services.behavior import analyze_behavior_context
from app.services.incidents import correlate_incident


BASE_TIME = datetime(2026, 9, 29, 8, 0, tzinfo=timezone.utc)


def event(
    event_id,
    application_id=1,
    seconds=0,
    *,
    risk_level="High",
    action="block",
    endpoint="/search",
    event_type="request_observation",
    request_id=None,
    matched_rules=None,
):
    return {
        "id": event_id,
        "application_id": application_id,
        "timestamp": (BASE_TIME + timedelta(seconds=seconds)).isoformat(),
        "risk_level": risk_level,
        "risk_score": 80 if risk_level != "Low" else 5,
        "action": action,
        "endpoint": endpoint,
        "event_type": event_type,
        "request_id": request_id,
        "matched_rules": matched_rules or ["R001"],
    }


class Phase7IncidentTests(unittest.TestCase):
    def test_empty_history_returns_single_high_risk_incident(self):
        result = correlate_incident(1, event(1), [])

        self.assertIsNotNone(result)
        self.assertTrue(result["single_event_incident"])
        self.assertEqual(result["event_count"], 1)

    def test_unrelated_events_are_not_correlated(self):
        result = correlate_incident(
            1,
            event(3, seconds=20, risk_level="Low", action="allow",
                  endpoint="/checkout", matched_rules=["R003"]),
            [event(1, seconds=0, risk_level="Low", action="allow",
                   endpoint="/search", matched_rules=["R001"])],
        )

        self.assertIsNone(result)

    def test_related_events_are_correlated(self):
        result = correlate_incident(
            1,
            event(2, seconds=20),
            [event(1, seconds=0)],
        )

        self.assertEqual(result["event_count"], 2)
        self.assertEqual(result["event_ids"], [1, 2])

    def test_application_isolation(self):
        result = correlate_incident(
            1,
            event(2, application_id=1, seconds=20, endpoint="/checkout", matched_rules=["R003"]),
            [event(1, application_id=2, endpoint="/checkout", matched_rules=["R003"])],
        )

        self.assertTrue(result["single_event_incident"])
        self.assertEqual(result["event_ids"], [2])

    def test_time_window_boundary(self):
        result = correlate_incident(
            1,
            event(2, seconds=INCIDENT_CORRELATION_WINDOW_SECONDS + 1),
            [event(1, seconds=0)],
        )

        self.assertTrue(result["single_event_incident"])
        self.assertEqual(result["event_ids"], [2])

    def test_endpoint_correlation_uses_normalized_endpoint(self):
        result = correlate_incident(
            1,
            event(2, seconds=20, endpoint="/users/42?view=full"),
            [event(1, seconds=0, endpoint="/users/41")],
        )

        self.assertIn("same normalized endpoint", result["correlation_reasons"])
        self.assertEqual(result["normalized_endpoints"], ["/users/:id"])

    def test_detection_pattern_correlation(self):
        result = correlate_incident(
            1,
            event(2, seconds=20, endpoint="/checkout", matched_rules=["R002"]),
            [event(1, seconds=0, endpoint="/search", matched_rules=["R002"])],
        )

        self.assertTrue(
            any("overlapping detection patterns" in reason for reason in result["correlation_reasons"])
        )

    def test_risk_and_action_context_is_represented(self):
        result = correlate_incident(
            1,
            event(2, seconds=20, risk_level="Critical", action="block_and_alert"),
            [event(1, seconds=0, risk_level="High", action="block")],
        )

        self.assertEqual(result["risk_levels"], ["Critical", "High"])
        self.assertEqual(result["actions"], ["block", "block_and_alert"])

    def test_incident_id_is_deterministic(self):
        current = event(2, seconds=20)
        history = [event(1)]

        first = correlate_incident(1, current, history)
        second = correlate_incident(1, current, history)

        self.assertEqual(first["incident_id"], second["incident_id"])
        self.assertTrue(first["incident_id"].startswith("inc_"))

    def test_correlation_reason_is_explainable(self):
        result = correlate_incident(1, event(2, seconds=20), [event(1)])

        self.assertTrue(result["correlation_reasons"])
        self.assertIn("same normalized endpoint", result["correlation_reasons"])

    def test_history_is_bounded(self):
        history = [
            event(index, seconds=index)
            for index in range(1, INCIDENT_MAX_RECENT_EVENTS + 20)
        ]
        result = correlate_incident(
            1,
            event(999, seconds=INCIDENT_MAX_RECENT_EVENTS + 20),
            history,
        )

        self.assertLessEqual(result["event_count"], INCIDENT_MAX_RECENT_EVENTS + 1)

    def test_missing_optional_metadata_does_not_crash(self):
        current = {
            "id": 2,
            "application_id": 1,
            "timestamp": BASE_TIME.isoformat(),
            "risk_level": "High",
            "action": "block",
        }

        result = correlate_incident(1, current, [{}])

        self.assertIsNotNone(result)
        self.assertEqual(result["normalized_endpoints"], [])

    def test_phase6_behavior_context_is_consumed_without_modification(self):
        current = event(2, seconds=20)
        history = [event(1)]
        behavior = analyze_behavior_context(1, current, history)
        original = dict(behavior)

        incident = correlate_incident(
            1,
            current,
            history,
            behavior_context=behavior,
        )

        self.assertEqual(incident["behavior_context"], original)
        self.assertEqual(behavior, original)

    def test_repeated_execution_is_identical(self):
        current = event(3, seconds=20, matched_rules=["R003"])
        history = [
            event(1, matched_rules=["R001"]),
            event(2, seconds=10, matched_rules=["R003"]),
        ]

        first = correlate_incident(1, current, history)
        second = correlate_incident(1, current, history)

        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()

import unittest
from datetime import datetime, timedelta, timezone
import tempfile
from pathlib import Path

from app.config import (
    BEHAVIOR_BURST_EVENT_THRESHOLD,
    BEHAVIOR_BURST_WINDOW_SECONDS,
    BEHAVIOR_MAX_RECENT_EVENTS,
    BEHAVIOR_WINDOW_SECONDS,
)
from app.services.behavior import (
    analyze_behavior_context,
    analyze_persisted_behavior_context,
)
from app.database import initialize_database


BASE_TIME = datetime(2026, 9, 29, 8, 0, tzinfo=timezone.utc)


def event(
    event_id,
    application_id=1,
    seconds=0,
    *,
    risk_level="Low",
    action="allow",
    endpoint="/search",
    matched_rules=None,
):
    return {
        "id": event_id,
        "application_id": application_id,
        "timestamp": (BASE_TIME + timedelta(seconds=seconds)).isoformat(),
        "risk_level": risk_level,
        "action": action,
        "rule_score": 80 if risk_level != "Low" else 0,
        "hybrid_signal": 0.8 if risk_level != "Low" else 0.0,
        "endpoint": endpoint,
        "matched_rules": matched_rules or [],
    }


class Phase6BehaviorTests(unittest.TestCase):
    def test_no_recent_events_is_neutral(self):
        result = analyze_behavior_context(1, event(1), [])

        self.assertEqual(result["behavioral_score"], 0)
        self.assertEqual(result["recent_event_count"], 0)
        self.assertFalse(result["repeated_activity"])

    def test_one_isolated_benign_event_is_neutral(self):
        result = analyze_behavior_context(
            1,
            event(2, seconds=10),
            [event(1, seconds=0)],
        )

        self.assertEqual(result["behavioral_score"], 0)
        self.assertFalse(result["burst_activity"])

    def test_repeated_suspicious_events_trigger_repetition(self):
        result = analyze_behavior_context(
            1,
            event(3, seconds=20, risk_level="High", action="block", matched_rules=["R001"]),
            [
                event(2, seconds=10, risk_level="High", action="block", matched_rules=["R001"]),
                event(1, seconds=0, risk_level="Critical", action="block_and_alert", matched_rules=["R002"]),
            ],
        )

        self.assertTrue(result["repeated_activity"])
        self.assertIn("Repeated suspicious activity", result["reasons"][0])

    def test_repeated_endpoint_targeting_triggers_endpoint_signal(self):
        result = analyze_behavior_context(
            1,
            event(3, seconds=20, risk_level="High", action="block", endpoint="/users/42"),
            [
                event(2, seconds=10, risk_level="High", action="block", endpoint="/users/41"),
                event(1, seconds=0, risk_level="High", action="block", endpoint="/users/40"),
            ],
        )

        self.assertTrue(result["endpoint_repetition"])
        self.assertEqual(result["normalized_endpoint"], "/users/:id")

    def test_high_event_frequency_triggers_burst_signal(self):
        history = [
            event(index, seconds=index)
            for index in range(1, BEHAVIOR_BURST_EVENT_THRESHOLD)
        ]
        result = analyze_behavior_context(
            1,
            event(99, seconds=BEHAVIOR_BURST_WINDOW_SECONDS - 1),
            history,
        )

        self.assertTrue(result["burst_activity"])

    def test_multiple_detection_patterns_trigger_diversity_signal(self):
        result = analyze_behavior_context(
            1,
            event(3, seconds=20, risk_level="High", action="block", matched_rules=["R003"]),
            [
                event(2, seconds=10, risk_level="High", action="block", matched_rules=["R001"]),
                event(1, seconds=0, risk_level="High", action="block", matched_rules=["R002"]),
            ],
        )

        self.assertTrue(result["pattern_diversity"])
        self.assertEqual(result["pattern_count"], 3)

    def test_other_application_does_not_affect_context(self):
        result = analyze_behavior_context(
            1,
            event(3, application_id=1, seconds=20, risk_level="High", action="block"),
            [
                event(2, application_id=2, seconds=10, risk_level="High", action="block"),
                event(1, application_id=2, seconds=0, risk_level="High", action="block"),
            ],
        )

        self.assertEqual(result["recent_event_count"], 0)
        self.assertFalse(result["repeated_activity"])

    def test_events_outside_window_do_not_affect_context(self):
        result = analyze_behavior_context(
            1,
            event(3, seconds=BEHAVIOR_WINDOW_SECONDS + 1),
            [
                event(
                    2,
                    seconds=0,
                    risk_level="High",
                    action="block",
                )
            ],
        )

        self.assertEqual(result["recent_event_count"], 0)

    def test_history_is_bounded(self):
        history = [
            event(index, seconds=index)
            for index in range(1, BEHAVIOR_MAX_RECENT_EVENTS + 20)
        ]
        result = analyze_behavior_context(
            1,
            event(999, seconds=BEHAVIOR_MAX_RECENT_EVENTS + 20),
            history,
        )

        self.assertEqual(result["recent_event_count"], BEHAVIOR_MAX_RECENT_EVENTS)

    def test_missing_optional_metadata_does_not_crash(self):
        current = {
            "application_id": 1,
            "timestamp": BASE_TIME.isoformat(),
            "risk_level": "Low",
            "action": "allow",
        }

        result = analyze_behavior_context(1, current, [{}])

        self.assertEqual(result["behavioral_score"], 0)
        self.assertIsNone(result["normalized_endpoint"])

    def test_behavior_does_not_modify_existing_detector_result(self):
        current = event(2, seconds=10, risk_level="High", action="block")
        original = dict(current)

        analyze_behavior_context(1, current, [event(1, risk_level="High", action="block")])

        self.assertEqual(current, original)

    def test_behavior_is_deterministic(self):
        current = event(3, seconds=20, risk_level="High", action="block", matched_rules=["R003"])
        history = [
            event(1, risk_level="High", action="block", matched_rules=["R001"]),
            event(2, seconds=10, risk_level="High", action="block", matched_rules=["R002"]),
        ]

        self.assertEqual(
            analyze_behavior_context(1, current, history),
            analyze_behavior_context(1, current, history),
        )

    def test_persisted_context_uses_application_bounded_query(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "behavior.sqlite3"
            initialize_database(database_path)
            result = analyze_persisted_behavior_context(
                1,
                event(3, seconds=20, risk_level="High", action="block"),
                database_path,
            )

        self.assertEqual(result["recent_event_count"], 0)


if __name__ == "__main__":
    unittest.main()

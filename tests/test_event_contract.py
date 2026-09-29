import unittest

from app.config import (
    MAX_EVENT_INPUT_LENGTH,
    MAX_METADATA_ITEMS,
    METADATA_TRUST_LEVELS,
    RETENTION_MODES,
)
from app.services.event_contract import SecurityEventContract


class EventContractTests(unittest.TestCase):
    def test_valid_event_is_normalized(self):
        contract = SecurityEventContract.from_mapping(
            {
                "event_type": "input_analysis",
                "input_fields": {"comment": "  ordinary text  "},
                "application_slug": "demo-site",
                "request_id": "request-1",
                "http_method": "post",
                "endpoint": " /search ",
                "metadata": {
                    "client_ip": {"value": "127.0.0.1", "trust": "observed"},
                },
            }
        )

        self.assertEqual(contract.input_fields["comment"], "ordinary text")
        self.assertEqual(contract.http_method, "POST")
        self.assertEqual(contract.endpoint, "/search")
        self.assertEqual(contract.metadata["client_ip"].trust, "observed")
        self.assertEqual(contract.retention_mode, "truncated")

    def test_defaults_support_legacy_browser_flow(self):
        contract = SecurityEventContract.from_mapping(
            {"input_fields": {"comment": "text"}}
        )

        self.assertEqual(contract.event_type, "input_analysis")
        self.assertEqual(contract.application_slug, "legacy-local")
        self.assertEqual(contract.retention_mode, "truncated")
        self.assertEqual(contract.metadata, {})

    def test_to_dict_preserves_trust_labels(self):
        contract = SecurityEventContract.from_mapping(
            {
                "input_fields": {"comment": "text"},
                "metadata": {
                    "user_agent": {"value": "Demo/1.0", "trust": "supplied"},
                    "browser_family": {"value": "DemoBrowser", "trust": "derived"},
                },
            }
        )

        self.assertEqual(
            contract.to_dict()["metadata"],
            {
                "user_agent": {"value": "Demo/1.0", "trust": "supplied"},
                "browser_family": {"value": "DemoBrowser", "trust": "derived"},
            },
        )

    def test_invalid_event_type_is_rejected(self):
        with self.assertRaises(ValueError):
            SecurityEventContract.from_mapping(
                {"event_type": "unsupported", "input_fields": {"comment": "text"}}
            )

    def test_empty_input_fields_are_rejected(self):
        with self.assertRaises(ValueError):
            SecurityEventContract.from_mapping({"input_fields": {}})

    def test_combined_input_limit_is_enforced(self):
        with self.assertRaises(ValueError):
            SecurityEventContract.from_mapping(
                {
                    "input_fields": {
                        "comment": "x" * (MAX_EVENT_INPUT_LENGTH + 1)
                    }
                }
            )

    def test_metadata_trust_level_is_restricted(self):
        self.assertEqual(
            METADATA_TRUST_LEVELS,
            {"observed", "supplied", "derived"},
        )
        with self.assertRaises(ValueError):
            SecurityEventContract.from_mapping(
                {
                    "input_fields": {"comment": "text"},
                    "metadata": {
                        "client_ip": {"value": "127.0.0.1", "trust": "authoritative"}
                    },
                }
            )

    def test_metadata_item_limit_is_enforced(self):
        metadata = {
            f"key-{index}": {"value": "value", "trust": "supplied"}
            for index in range(MAX_METADATA_ITEMS + 1)
        }
        with self.assertRaises(ValueError):
            SecurityEventContract.from_mapping(
                {"input_fields": {"comment": "text"}, "metadata": metadata}
            )

    def test_retention_mode_is_restricted(self):
        self.assertIn("truncated", RETENTION_MODES)
        with self.assertRaises(ValueError):
            SecurityEventContract.from_mapping(
                {
                    "input_fields": {"comment": "text"},
                    "retention_mode": "unlimited",
                }
            )

    def test_metadata_values_must_be_objects(self):
        with self.assertRaises(ValueError):
            SecurityEventContract.from_mapping(
                {
                    "input_fields": {"comment": "text"},
                    "metadata": {"client_ip": "127.0.0.1"},
                }
            )


if __name__ == "__main__":
    unittest.main()

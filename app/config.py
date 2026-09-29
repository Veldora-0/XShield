"""Configuration values shared by the current app and future integrations."""

INTEGRATION_API_VERSION = "v1"

SUPPORTED_EVENT_TYPES = frozenset(
    {
        "input_analysis",
        "request_observation",
    }
)

METADATA_TRUST_LEVELS = frozenset({"observed", "supplied", "derived"})
RETENTION_MODES = frozenset({"full", "truncated", "hash_only", "redacted", "disabled"})

MAX_EVENT_INPUT_LENGTH = 10_000
MAX_STORED_INPUT_LENGTH = 2_000
MAX_EVENT_FIELDS = 32
MAX_FIELD_NAME_LENGTH = 64
MAX_REQUEST_ID_LENGTH = 128
MAX_ENDPOINT_LENGTH = 512
MAX_METADATA_ITEMS = 32
MAX_METADATA_KEY_LENGTH = 64
MAX_METADATA_VALUE_LENGTH = 512

# Phase 6 behavioral/context heuristics. These are bounded project settings,
# not universal security standards.
BEHAVIOR_WINDOW_SECONDS = 300
BEHAVIOR_BURST_WINDOW_SECONDS = 60
BEHAVIOR_MAX_RECENT_EVENTS = 100
BEHAVIOR_REPEATED_SUSPICIOUS_THRESHOLD = 3
BEHAVIOR_ENDPOINT_REPETITION_THRESHOLD = 3
BEHAVIOR_BURST_EVENT_THRESHOLD = 5
BEHAVIOR_PATTERN_DIVERSITY_THRESHOLD = 2

# Phase 7 incident-correlation heuristics. These are bounded project settings,
# not universal security standards.
INCIDENT_CORRELATION_WINDOW_SECONDS = 300
INCIDENT_MAX_RECENT_EVENTS = 100
INCIDENT_ENDPOINT_MATCH_ENABLED = True
INCIDENT_SINGLE_EVENT_RISK_LEVELS = frozenset({"High", "Critical"})

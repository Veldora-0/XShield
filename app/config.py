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

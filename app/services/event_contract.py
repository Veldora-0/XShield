"""Validated internal event contract for future XShield integrations."""

from dataclasses import dataclass
from collections.abc import Mapping

from app.config import (
    MAX_ENDPOINT_LENGTH,
    MAX_EVENT_FIELDS,
    MAX_EVENT_INPUT_LENGTH,
    MAX_FIELD_NAME_LENGTH,
    MAX_METADATA_ITEMS,
    MAX_METADATA_KEY_LENGTH,
    MAX_METADATA_VALUE_LENGTH,
    MAX_REQUEST_ID_LENGTH,
    METADATA_TRUST_LEVELS,
    RETENTION_MODES,
    SUPPORTED_EVENT_TYPES,
)


def _bounded_text(value: object, *, name: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string.")
    cleaned = value.strip()
    if len(cleaned) > limit:
        raise ValueError(f"{name} must be {limit} characters or fewer.")
    return cleaned


@dataclass(frozen=True)
class MetadataValue:
    """A metadata value with an explicit trust classification."""

    value: str
    trust: str

    @classmethod
    def from_mapping(cls, value: object, *, name: str) -> "MetadataValue":
        if not isinstance(value, Mapping):
            raise ValueError(f"{name} must contain value and trust.")
        text = _bounded_text(
            value.get("value"),
            name=f"{name}.value",
            limit=MAX_METADATA_VALUE_LENGTH,
        )
        trust = _bounded_text(
            value.get("trust"),
            name=f"{name}.trust",
            limit=16,
        )
        if trust not in METADATA_TRUST_LEVELS:
            raise ValueError(
                f"{name}.trust must be one of: "
                f"{', '.join(sorted(METADATA_TRUST_LEVELS))}."
            )
        return cls(value=text, trust=trust)

    def to_dict(self) -> dict[str, str]:
        return {"value": self.value, "trust": self.trust}


@dataclass(frozen=True)
class SecurityEventContract:
    """Normalized event shape shared by browser and future API inputs."""

    event_type: str
    input_fields: dict[str, str]
    application_slug: str = "legacy-local"
    request_id: str | None = None
    http_method: str | None = None
    endpoint: str | None = None
    metadata: dict[str, MetadataValue] | None = None
    retention_mode: str = "truncated"

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, object],
    ) -> "SecurityEventContract":
        if not isinstance(payload, Mapping):
            raise ValueError("Event payload must be an object.")

        event_type = _bounded_text(
            payload.get("event_type", "input_analysis"),
            name="event_type",
            limit=64,
        )
        if event_type not in SUPPORTED_EVENT_TYPES:
            raise ValueError(
                f"event_type must be one of: "
                f"{', '.join(sorted(SUPPORTED_EVENT_TYPES))}."
            )

        raw_fields = payload.get("input_fields", {})
        if not isinstance(raw_fields, Mapping) or not raw_fields:
            raise ValueError("input_fields must be a non-empty object.")
        if len(raw_fields) > MAX_EVENT_FIELDS:
            raise ValueError(f"input_fields must contain {MAX_EVENT_FIELDS} or fewer fields.")

        input_fields: dict[str, str] = {}
        total_length = 0
        for raw_name, raw_value in raw_fields.items():
            name = _bounded_text(
                raw_name,
                name="input field name",
                limit=MAX_FIELD_NAME_LENGTH,
            )
            if not name:
                raise ValueError("Input field names cannot be empty.")
            value = _bounded_text(
                raw_value,
                name=f"input_fields[{name}]",
                limit=MAX_EVENT_INPUT_LENGTH,
            )
            total_length += len(value)
            if total_length > MAX_EVENT_INPUT_LENGTH:
                raise ValueError(
                    f"Combined input fields must be {MAX_EVENT_INPUT_LENGTH} "
                    "characters or fewer."
                )
            input_fields[name] = value

        application_slug = _bounded_text(
            payload.get("application_slug", "legacy-local"),
            name="application_slug",
            limit=128,
        )
        if not application_slug:
            raise ValueError("application_slug cannot be empty.")

        request_id = payload.get("request_id")
        if request_id is not None:
            request_id = _bounded_text(
                request_id,
                name="request_id",
                limit=MAX_REQUEST_ID_LENGTH,
            )
            if not request_id:
                request_id = None

        http_method = payload.get("http_method")
        if http_method is not None:
            http_method = _bounded_text(
                http_method,
                name="http_method",
                limit=16,
            ).upper()
            if not http_method:
                http_method = None

        endpoint = payload.get("endpoint")
        if endpoint is not None:
            endpoint = _bounded_text(
                endpoint,
                name="endpoint",
                limit=MAX_ENDPOINT_LENGTH,
            )
            if not endpoint:
                endpoint = None

        raw_metadata = payload.get("metadata", {})
        if not isinstance(raw_metadata, Mapping):
            raise ValueError("metadata must be an object.")
        if len(raw_metadata) > MAX_METADATA_ITEMS:
            raise ValueError(f"metadata must contain {MAX_METADATA_ITEMS} or fewer items.")

        metadata: dict[str, MetadataValue] = {}
        for raw_key, raw_value in raw_metadata.items():
            key = _bounded_text(
                raw_key,
                name="metadata key",
                limit=MAX_METADATA_KEY_LENGTH,
            )
            if not key:
                raise ValueError("Metadata keys cannot be empty.")
            metadata[key] = MetadataValue.from_mapping(raw_value, name=f"metadata[{key}]")

        retention_mode = _bounded_text(
            payload.get("retention_mode", "truncated"),
            name="retention_mode",
            limit=32,
        )
        if retention_mode not in RETENTION_MODES:
            raise ValueError(
                f"retention_mode must be one of: "
                f"{', '.join(sorted(RETENTION_MODES))}."
            )

        return cls(
            event_type=event_type,
            input_fields=input_fields,
            application_slug=application_slug,
            request_id=request_id,
            http_method=http_method,
            endpoint=endpoint,
            metadata=metadata,
            retention_mode=retention_mode,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "event_type": self.event_type,
            "input_fields": dict(self.input_fields),
            "application_slug": self.application_slug,
            "request_id": self.request_id,
            "http_method": self.http_method,
            "endpoint": self.endpoint,
            "metadata": {
                key: value.to_dict()
                for key, value in (self.metadata or {}).items()
            },
            "retention_mode": self.retention_mode,
        }

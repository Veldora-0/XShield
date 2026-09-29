import re


FIELD_LIMITS = {
    "username": 100,
    "search_query": 200,
    "comment": 1000,
}

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def validate_input(form_data):
    """Return cleaned values and field errors for the Phase 3 form."""
    values = {
        field: form_data.get(field, "").strip()
        for field in FIELD_LIMITS
    }
    errors = {}

    for field, value in values.items():
        if not value:
            errors[field] = "This field is required."
        elif len(value) > FIELD_LIMITS[field]:
            errors[field] = (
                f"This field must be {FIELD_LIMITS[field]} characters or fewer."
            )

    username = values["username"]
    if username and len(username) <= FIELD_LIMITS["username"]:
        if not USERNAME_PATTERN.fullmatch(username):
            errors["username"] = (
                "Use only letters, numbers, underscores, or hyphens."
            )

    return values, errors

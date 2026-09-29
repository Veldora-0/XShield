"""Local application and API-key management for development/testing."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.database import (
    DEFAULT_DATABASE_PATH,
    create_application,
    get_application_by_slug,
    initialize_database,
    list_applications,
)
from app.services.api_keys import create_api_key, list_api_keys, revoke_api_key


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage XShield applications and API keys.")
    parser.add_argument("--database", default=str(DEFAULT_DATABASE_PATH))
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create-application")
    create.add_argument("slug")
    create.add_argument("name")
    create.add_argument("--description", default="")

    subparsers.add_parser("list-applications")

    key = subparsers.add_parser("create-api-key")
    key.add_argument("--application-id", type=int)
    key.add_argument("--slug")
    key.add_argument("--expires-at")

    subparsers.add_parser("list-api-keys")

    revoke = subparsers.add_parser("revoke-api-key")
    revoke.add_argument("api_key_id", type=int)
    return parser


def main() -> int:
    args = _parser().parse_args()
    initialize_database(args.database)

    if args.command == "create-application":
        result = create_application(
            args.slug, args.name, args.description, args.database
        )
    elif args.command == "list-applications":
        result = list_applications(args.database)
    elif args.command == "create-api-key":
        application_id = args.application_id
        if application_id is None and args.slug:
            application = get_application_by_slug(args.slug, args.database)
            if application is None:
                raise LookupError("Application not found.")
            application_id = application["id"]
        if application_id is None:
            raise ValueError("Provide --application-id or --slug.")
        result = create_api_key(application_id, args.database, args.expires_at)
        print("API key (displayed once):", result.pop("api_key"))
    elif args.command == "list-api-keys":
        result = list_api_keys(args.database)
    else:
        result = revoke_api_key(args.api_key_id, args.database)

    if result is not None:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LookupError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)

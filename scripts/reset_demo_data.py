"""Safe, explicit local demonstration data reset utility for XShield."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sqlite3
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.database import (
    DEFAULT_DATABASE_PATH,
    count_events,
    initialize_database,
    list_applications,
    reset_demo_events,
)
from app.services.api_keys import list_api_keys


REQUIRED_CONFIRMATION = "RESET"


def _parse_args(args: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Explicitly clear local XShield security event data for a fresh demonstration."
    )
    parser.add_argument(
        "--database",
        default=str(DEFAULT_DATABASE_PATH),
        help=f"Path to SQLite database (default: {DEFAULT_DATABASE_PATH})",
    )
    parser.add_argument(
        "--confirm",
        default=None,
        help="Provide the required confirmation string 'RESET' directly for non-interactive execution.",
    )
    return parser.parse_args(args)


def run_reset(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
    confirmation: str | None = None,
    interactive: bool = True,
) -> int:
    """Execute the local demonstration data reset workflow.

    Returns:
        0 on success, 1 on cancellation or failure.
    """
    db_path = Path(database_path)
    if not db_path.exists():
        print(f"Database file not found at: {db_path}")
        return 1

    # Ensure schema is initialized before querying
    initialize_database(db_path)

    try:
        events_before = count_events(db_path)
        apps_before = list_applications(db_path)
        keys_before = list_api_keys(db_path)
    except sqlite3.Error as exc:
        print(f"Failed to query database state: {exc}")
        return 1

    print("=" * 70)
    print("XShield Local Demonstration Data Reset")
    print("=" * 70)
    print()
    print("WARNING: This will delete local XShield security event data.")
    print("Applications and API keys will be preserved.")
    print()
    print("Current telemetry state:")
    print(f"  - Database: {db_path}")
    print(f"  - Recorded security events: {events_before}")
    print(f"  - Registered applications: {len(apps_before)}")
    print(f"  - Active API keys: {len(keys_before)}")
    print()

    # Determine confirmation string
    entered_confirmation = confirmation
    if entered_confirmation is None:
        if not interactive:
            print("Reset aborted: No confirmation provided in non-interactive mode.")
            return 1
        try:
            entered_confirmation = input(f"Type {REQUIRED_CONFIRMATION} to continue: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nReset aborted by user. No changes made.")
            return 1

    if entered_confirmation != REQUIRED_CONFIRMATION:
        print(f"\nReset aborted. Confirmation string did not match '{REQUIRED_CONFIRMATION}'. No changes made.")
        return 1

    # Perform atomic transactional reset
    try:
        deleted_count = reset_demo_events(db_path)
        events_after = count_events(db_path)
        apps_after = list_applications(db_path)
        keys_after = list_api_keys(db_path)

        if events_after != 0:
            raise RuntimeError(f"Expected 0 events after reset, found {events_after}")
        if len(apps_after) != len(apps_before):
            raise RuntimeError("Application count mismatch after reset")
        if len(keys_after) != len(keys_before):
            raise RuntimeError("API key count mismatch after reset")

    except Exception as exc:
        print(f"\nReset failed: {exc}")
        print("Transaction was rolled back. No data was deleted.")
        return 1

    print("\nDemo data reset complete.")
    print()
    print(f"Deleted security events: {deleted_count}")
    print(f"Applications preserved: {len(apps_after)}")
    print(f"API keys preserved: {len(keys_after)}")
    print()
    return 0


def main() -> int:
    args = _parse_args()
    return run_reset(
        database_path=args.database,
        confirmation=args.confirm,
        interactive=sys.stdin.isatty() if args.confirm is None else False,
    )


if __name__ == "__main__":
    sys.exit(main())

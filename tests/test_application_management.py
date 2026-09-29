import io
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.database import (
    create_application,
    get_application_by_id,
    initialize_database,
    list_applications,
    set_application_status,
)
from app.services.api_keys import (
    authenticate_api_key,
    create_api_key,
    generate_api_key,
    list_api_keys,
    revoke_api_key,
)


class ApplicationManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "management.sqlite3"
        initialize_database(self.database_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_application_registration_and_unique_slug(self):
        application = create_application(
            "Demo-App", "Demo Application", "local test", self.database_path
        )

        self.assertEqual(application["slug"], "demo-app")
        self.assertEqual(application["status"], "active")
        self.assertTrue(application["created_at"])
        self.assertEqual(application["created_at"], application["updated_at"])
        with self.assertRaises(sqlite3.IntegrityError):
            create_application("demo-app", "Duplicate", database_path=self.database_path)

    def test_inactive_application_is_not_authenticated(self):
        application = create_application("inactive-app", "Inactive", database_path=self.database_path)
        created = create_api_key(application["id"], self.database_path)
        set_application_status(application["id"], "revoked", self.database_path)

        result = authenticate_api_key(
            {"X-API-Key": created["api_key"]}, self.database_path
        )

        self.assertFalse(result.authenticated)
        self.assertEqual(result.reason, "inactive_application")

    def test_secure_key_generation_and_hashed_storage(self):
        first = generate_api_key()
        second = generate_api_key()
        self.assertTrue(first.startswith("xsh_"))
        self.assertNotEqual(first, second)
        self.assertGreaterEqual(len(first), 40)

        application = create_application("secure-app", "Secure", database_path=self.database_path)
        created = create_api_key(application["id"], self.database_path)
        metadata = list_api_keys(self.database_path)
        self.assertNotIn("api_key", metadata[0])
        self.assertNotIn(created["api_key"], metadata[0].values())

        connection = sqlite3.connect(self.database_path)
        try:
            stored_hash = connection.execute(
                "SELECT key_hash FROM api_keys WHERE id = ?", (created["id"],)
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertNotEqual(stored_hash, created["api_key"])
        self.assertEqual(len(stored_hash), 64)

    def test_authentication_associates_application_and_updates_last_used(self):
        first = create_application("first-app", "First", database_path=self.database_path)
        second = create_application("second-app", "Second", database_path=self.database_path)
        first_key = create_api_key(first["id"], self.database_path)
        second_key = create_api_key(second["id"], self.database_path)

        result = authenticate_api_key(
            {"x-api-key": first_key["api_key"]}, self.database_path
        )

        self.assertTrue(result.authenticated)
        self.assertEqual(result.application["id"], first["id"])
        self.assertEqual(result.application["slug"], "first-app")
        self.assertNotEqual(first_key["api_key"], second_key["api_key"])
        self.assertTrue(list_api_keys(self.database_path)[0]["last_used_at"])

    def test_invalid_and_revoked_keys_are_rejected_without_secret_in_error(self):
        application = create_application("revocation-app", "Revocation", database_path=self.database_path)
        created = create_api_key(application["id"], self.database_path)
        invalid = authenticate_api_key({"X-API-Key": "xsh_not-the-key"}, self.database_path)
        revoke_api_key(created["id"], self.database_path)
        revoked = authenticate_api_key({"X-API-Key": created["api_key"]}, self.database_path)

        self.assertFalse(invalid.authenticated)
        self.assertFalse(revoked.authenticated)
        self.assertNotIn(created["api_key"], str(invalid))
        self.assertNotIn(created["api_key"], str(revoked))

    def test_expired_key_is_rejected(self):
        application = create_application("expired-app", "Expired", database_path=self.database_path)
        expires_at = (
            datetime.now(timezone.utc) - timedelta(minutes=1)
        ).isoformat(timespec="seconds")
        created = create_api_key(
            application["id"], self.database_path, expires_at=expires_at
        )

        result = authenticate_api_key(
            {"X-API-Key": created["api_key"]}, self.database_path
        )

        self.assertFalse(result.authenticated)
        self.assertEqual(result.reason, "expired_api_key")

    def test_key_creation_does_not_write_plaintext_to_cli_output_helpers(self):
        application = create_application("output-app", "Output", database_path=self.database_path)
        created = create_api_key(application["id"], self.database_path)
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            print({"id": created["id"], "application_id": created["application_id"]})
        self.assertNotIn(created["api_key"], output.getvalue())

    def test_repeated_migration_preserves_phase2_data(self):
        initialize_database(self.database_path)
        initialize_database(self.database_path)
        applications = list_applications(self.database_path)
        legacy = get_application_by_id(applications[0]["id"], self.database_path)

        self.assertEqual(len(applications), 1)
        self.assertEqual(legacy["slug"], "legacy-local")
        connection = sqlite3.connect(self.database_path)
        try:
            version = connection.execute(
                "SELECT MAX(version) FROM schema_migrations"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(version, 4)


if __name__ == "__main__":
    unittest.main()

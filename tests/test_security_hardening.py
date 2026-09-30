import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from app.ml.predictor import _load_artifacts
from app.services.security_logger import log_security_event


class SecurityHardeningTests(unittest.TestCase):
    def test_oversized_request_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "hardening.sqlite3"
            app = create_app(
                {
                    "TESTING": True,
                    "DATABASE_PATH": str(database_path),
                    "MAX_CONTENT_LENGTH": 256,
                }
            )
            response = app.test_client().post(
                "/",
                data={
                    "username": "student_01",
                    "search_query": "security",
                    "comment": "x" * 1000,
                },
            )
            self.assertEqual(response.status_code, 413)

    def test_logging_failure_does_not_expose_exception_details(self):
        with tempfile.TemporaryDirectory() as directory:
            result = log_security_event(
                "test",
                {},
                Path(directory) / "events.sqlite3",
            )
        self.assertFalse(result["stored"])
        self.assertNotIn("KeyError", result["error"])
        self.assertNotIn("events.sqlite3", result["error"])

    def test_missing_model_artifacts_raise_clear_error(self):
        _load_artifacts.cache_clear()
        with patch("app.ml.predictor.VECTORIZER_PATH", Path("missing-vectorizer.joblib")), \
             patch("app.ml.predictor.MODEL_PATH", Path("missing-model.joblib")):
            with self.assertRaises(FileNotFoundError) as context:
                _load_artifacts()
        self.assertIn("Trained ML artifacts are missing", str(context.exception))
        _load_artifacts.cache_clear()

    def test_corrupted_model_artifacts_raise_generic_error(self):
        _load_artifacts.cache_clear()
        with tempfile.TemporaryDirectory() as directory:
            vectorizer_path = Path(directory) / "trusted-vectorizer.joblib"
            model_path = Path(directory) / "trusted-model.joblib"
            vectorizer_path.write_bytes(b"corrupt")
            model_path.write_bytes(b"corrupt")
            with patch(
                "app.ml.predictor.VECTORIZER_PATH",
                vectorizer_path,
            ), patch(
                "app.ml.predictor.MODEL_PATH",
                model_path,
            ), patch(
                "app.ml.predictor.joblib.load",
                side_effect=ValueError("pickle details"),
            ):
                with self.assertRaises(RuntimeError) as context:
                    _load_artifacts()
        self.assertIn("Trusted ML artifacts could not be loaded", str(context.exception))
        self.assertNotIn("pickle details", str(context.exception))
        _load_artifacts.cache_clear()


if __name__ == "__main__":
    unittest.main()

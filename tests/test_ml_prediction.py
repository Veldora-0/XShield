import json
import unittest
from pathlib import Path

import pandas as pd

from app.ml.predictor import MODEL_PATH, VECTORIZER_PATH, predict_text


ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "models" / "ml_training_report.json"


class MLPredictionTests(unittest.TestCase):
    def test_saved_artifacts_and_report_exist(self):
        self.assertTrue(VECTORIZER_PATH.exists())
        self.assertTrue(MODEL_PATH.exists())
        self.assertTrue(REPORT_PATH.exists())

    def test_benign_example_returns_valid_prediction_structure(self):
        result = predict_text("please update my account settings")

        self.assertIn(result["label"], {0, 1})
        self.assertIn(result["prediction"], {"benign", "xss"})
        self.assertGreaterEqual(result["probability"], 0.0)
        self.assertLessEqual(result["probability"], 1.0)

    def test_xss_test_example_returns_valid_prediction_structure(self):
        test_data = pd.read_csv(ROOT / "data" / "processed" / "xss_test.csv")
        xss_example = test_data.loc[test_data["label"] == 1, "text"].iloc[0]
        result = predict_text(xss_example)

        self.assertIn(result["label"], {0, 1})
        self.assertIn(result["prediction"], {"benign", "xss"})
        self.assertGreaterEqual(result["probability"], 0.0)
        self.assertLessEqual(result["probability"], 1.0)

    def test_prediction_does_not_modify_saved_artifacts(self):
        before = (VECTORIZER_PATH.stat().st_mtime_ns, MODEL_PATH.stat().st_mtime_ns)
        predict_text("ordinary search text")
        after = (VECTORIZER_PATH.stat().st_mtime_ns, MODEL_PATH.stat().st_mtime_ns)

        self.assertEqual(before, after)

    def test_training_report_contains_actual_configuration(self):
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

        self.assertEqual(report["training_samples"], 24327)
        self.assertEqual(report["test_samples"], 3967)
        self.assertEqual(report["tfidf_configuration"]["fit_on"], "training text only")
        self.assertEqual(
            report["logistic_regression_configuration"]["class_weight"],
            "balanced",
        )


if __name__ == "__main__":
    unittest.main()

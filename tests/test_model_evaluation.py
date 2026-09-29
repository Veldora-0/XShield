import json
import unittest
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "reports" / "ml_evaluation.json"
PREDICTIONS_PATH = ROOT / "reports" / "ml_test_predictions.csv"


class ModelEvaluationTests(unittest.TestCase):
    def test_evaluation_report_contains_actual_test_metrics(self):
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

        self.assertEqual(report["dataset"]["samples"], 3967)
        self.assertEqual(report["dataset"]["positive_class"]["meaning"], "XSS")
        self.assertEqual(report["confusion_matrix"]["labels"], [0, 1])
        for value in report["metrics"].values():
            self.assertGreaterEqual(value, 0.0)
            self.assertLessEqual(value, 1.0)

    def test_confusion_matrix_counts_match_test_predictions(self):
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        predictions = pd.read_csv(PREDICTIONS_PATH)

        self.assertEqual(len(predictions), report["dataset"]["samples"])
        self.assertEqual(
            int((predictions["actual_label"] == 0).sum()),
            report["confusion_matrix"]["true_negative"]
            + report["confusion_matrix"]["false_positive"],
        )
        self.assertEqual(
            int((predictions["actual_label"] == 1).sum()),
            report["confusion_matrix"]["false_negative"]
            + report["confusion_matrix"]["true_positive"],
        )
        self.assertEqual(
            int((predictions["error_type"] == "false_positive").sum()),
            report["misclassifications"]["false_positive_count"],
        )
        self.assertEqual(
            int((predictions["error_type"] == "false_negative").sum()),
            report["misclassifications"]["false_negative_count"],
        )

    def test_misclassification_examples_have_expected_labels(self):
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

        for example in report["misclassifications"]["representative_false_positives"]:
            self.assertEqual(example["actual_label"], 0)
            self.assertEqual(example["predicted_label"], 1)
        for example in report["misclassifications"]["representative_false_negatives"]:
            self.assertEqual(example["actual_label"], 1)
            self.assertEqual(example["predicted_label"], 0)


if __name__ == "__main__":
    unittest.main()

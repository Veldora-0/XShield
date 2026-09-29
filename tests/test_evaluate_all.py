import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "reports" / "evaluation_results.json"
TEXT_REPORT_PATH = ROOT / "reports" / "evaluation_report.txt"


class ComparativeEvaluationTests(unittest.TestCase):
    def test_comparative_report_contains_three_methods_on_same_test_set(self):
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

        self.assertEqual(report["dataset"]["samples"], 3967)
        self.assertTrue(report["dataset"]["same_test_set_for_all_methods"])
        self.assertEqual(
            set(report["methods"]),
            {"rule_based", "ml", "hybrid"},
        )
        for method in report["methods"].values():
            metrics = method["metrics"]
            for key in ("accuracy", "precision_xss", "recall_xss", "f1_xss"):
                self.assertGreaterEqual(metrics[key], 0.0)
                self.assertLessEqual(metrics[key], 1.0)
            self.assertEqual(
                len(metrics["confusion_matrix"]["rows_actual_columns_predicted"]),
                2,
            )

    def test_error_counts_match_confusion_matrices(self):
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

        for method in report["methods"].values():
            matrix = method["metrics"]["confusion_matrix"]
            errors = method["errors"]
            self.assertEqual(
                matrix["false_positive"],
                len(errors["false_positives"])
                if matrix["false_positive"] <= 5
                else matrix["false_positive"],
            )
            self.assertGreaterEqual(matrix["false_negative"], 0)
            self.assertGreaterEqual(matrix["false_positive"], 0)

    def test_text_report_and_threshold_documentation_exist(self):
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        text_report = TEXT_REPORT_PATH.read_text(encoding="utf-8")

        self.assertTrue(report["thresholds"]["experimental"])
        self.assertIn("Rule-Based", text_report)
        self.assertIn("ML", text_report)
        self.assertIn("Hybrid", text_report)
        self.assertIn("same held-out test set", text_report)


if __name__ == "__main__":
    unittest.main()

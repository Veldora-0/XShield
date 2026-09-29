import json
import unittest
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
PROCESSED = ROOT / "data" / "processed"


class DatasetPreparationTests(unittest.TestCase):
    def test_processed_dataset_has_expected_schema_and_labels(self):
        dataset = pd.read_csv(PROCESSED / "xss_dataset.csv")

        self.assertEqual(list(dataset.columns), ["text", "label"])
        self.assertTrue(dataset["text"].notna().all())
        self.assertTrue(dataset["text"].str.len().gt(0).all())
        self.assertTrue(set(dataset["label"].unique()).issubset({0, 1}))
        self.assertEqual(set(dataset["label"].unique()), {0, 1})

    def test_train_and_test_sets_have_no_normalized_text_overlap(self):
        train = pd.read_csv(PROCESSED / "xss_train.csv")
        test = pd.read_csv(PROCESSED / "xss_test.csv")

        normalize = lambda values: {
            " ".join(str(value).casefold().split()) for value in values
        }
        self.assertTrue(normalize(train["text"]).isdisjoint(normalize(test["text"])))
        self.assertEqual(len(train) + len(test), len(pd.read_csv(PROCESSED / "xss_dataset.csv")))
        self.assertEqual(set(train["label"].unique()), {0, 1})
        self.assertEqual(set(test["label"].unique()), {0, 1})

    def test_report_records_real_preparation_metadata(self):
        report = json.loads((PROCESSED / "dataset_report.json").read_text(encoding="utf-8"))

        self.assertEqual(report["random_seed"], 42)
        self.assertEqual(report["test_size"], 0.2)
        self.assertEqual(report["canonical_train_test_overlap"], 0)
        self.assertEqual(report["label_mapping"]["0"], "BENIGN (source attack_type=norm)")
        self.assertEqual(report["label_mapping"]["1"], "XSS (source attack_type=xss)")


if __name__ == "__main__":
    unittest.main()

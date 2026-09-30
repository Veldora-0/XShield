"""Unit tests for ML Benchmark v2 pipeline scaffolding, qualitative battery, and regression gate."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts.qualitative_suite import (
    QUALITATIVE_TEST_CASES,
    evaluate_qualitative_suite,
)
from scripts.regression_gate import RegressionGate
from scripts.v2_dataset_pipeline import (
    DatasetIngestionPipeline,
    canonicalize_payload,
    compute_canonical_hash,
)


class TestV2PipelineScaffolding(unittest.TestCase):
    """Test suite covering the Benchmark v2 dataset, qualitative suite, and regression gate."""

    def test_canonicalization_and_hashing(self) -> None:
        raw_1 = "  <SCRIPT>alert('1')</SCRIPT>  "
        raw_2 = "<script> alert('1') </script>"
        raw_encoded = "%3cscript%3ealert('1')%3c/script%3e"

        canon_1 = canonicalize_payload(raw_1)
        canon_2 = canonicalize_payload(raw_2)
        canon_enc = canonicalize_payload(raw_encoded)

        self.assertEqual(canon_1, "<script>alert('1')</script>")
        self.assertEqual(canon_enc, "<script>alert('1')</script>")
        self.assertEqual(compute_canonical_hash(canon_1), compute_canonical_hash(canon_enc))

    def test_txt_csv_json_ingestion_and_provenance(self) -> None:
        pipeline = DatasetIngestionPipeline()

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # 1. Ingest TXT
            txt_file = tmp_path / "payloads.txt"
            txt_file.write_text(
                "# Comment line\n<script>alert(1)</script>\n\n<svg onload=alert(1)>\n",
                encoding="utf-8",
            )
            txt_count = pipeline.ingest_txt_file(
                txt_file,
                label=1,
                source="OWASP-Test",
                license="CC-BY-4.0",
                url_reference="https://owasp.org",
            )
            self.assertEqual(txt_count, 2)

            # 2. Ingest CSV
            csv_file = tmp_path / "data.csv"
            csv_file.write_text(
                "payload_str,target_label,id_val\n"
                "order_123,benign,C-1\n"
                "<script>alert(1)</script>,malicious,C-2\n",  # Duplicate of TXT line 1
                encoding="utf-8",
            )
            csv_count = pipeline.ingest_csv_file(
                csv_file,
                text_column="payload_str",
                label_column="target_label",
                label_mapping={"benign": 0, "malicious": 1},
                source="Internal-Audit",
                id_column="id_val",
                license="MIT",
            )
            self.assertEqual(csv_count, 2)

            # 3. Ingest JSON
            json_file = tmp_path / "items.json"
            json_file.write_text(
                json.dumps(
                    [
                        {"query": "hello world", "status": "clean", "uuid": "J-1"},
                        {"query": "javascript:alert(1)", "status": "bad", "uuid": "J-2"},
                    ]
                ),
                encoding="utf-8",
            )
            json_count = pipeline.ingest_json_file(
                json_file,
                text_key="query",
                label_key="status",
                label_mapping={"clean": 0, "bad": 1},
                source="Web-Log-Export",
                id_key="uuid",
            )
            self.assertEqual(json_count, 2)

        # Total ingested: 2 (txt) + 2 (csv) + 2 (json) = 6
        self.assertEqual(len(pipeline.samples), 6)

        # Unique samples: <script>alert(1)</script> was ingested twice
        unique_samples = pipeline.get_unique_samples()
        self.assertEqual(len(unique_samples), 5)

        manifest = pipeline.generate_manifest()
        self.assertEqual(manifest["total_ingested"], 6)
        self.assertEqual(manifest["unique_samples"], 5)
        self.assertEqual(manifest["duplicate_samples_pruned"], 1)
        self.assertIn("OWASP-Test", manifest["sources"])
        self.assertIn("Internal-Audit", manifest["sources"])
        self.assertIn("Web-Log-Export", manifest["sources"])

    def test_benchmark_v1_non_overlap_verification(self) -> None:
        pipeline = DatasetIngestionPipeline()
        # Ingest a harmless unique string
        pipeline.ingest_record(
            "unique_test_string_not_in_benchmark_12345",
            label=0,
            source="MockSource",
            source_id="MS-1",
        )
        overlap = pipeline.verify_no_overlap_with_benchmark_v1()
        self.assertEqual(overlap, [])

        # Ingest a known Benchmark v1 sample
        known_v1_payload = "</script><script>alert(1)</script>"
        pipeline.ingest_record(
            known_v1_payload,
            label=1,
            source="MockSource",
            source_id="MS-2",
        )
        overlap_with_v1 = pipeline.verify_no_overlap_with_benchmark_v1()
        self.assertIn(known_v1_payload, overlap_with_v1)

    def test_qualitative_suite_structure_and_coverage(self) -> None:
        self.assertGreaterEqual(len(QUALITATIVE_TEST_CASES), 25)
        categories = {case.category for case in QUALITATIVE_TEST_CASES}
        expected_categories = {"A", "B", "C", "D", "E", "F", "G", "H"}
        self.assertTrue(expected_categories.issubset(categories))

        report = evaluate_qualitative_suite()
        self.assertIn("pass_rate_pct", report)
        self.assertIn("category_summary", report)

        # Crucial check: Benign categories G and H must have 0 failures on baseline
        cat_g = report["category_summary"].get("G", {})
        cat_h = report["category_summary"].get("H", {})
        self.assertEqual(cat_g.get("failed", -1), 0, "Developer discussions must never be blocked")
        self.assertEqual(cat_h.get("failed", -1), 0, "Enterprise text must never be blocked")

    def test_regression_gate_baseline_execution(self) -> None:
        gate = RegressionGate()
        result = gate.run_all_gates()

        self.assertEqual(result["verdict"], "ACCEPT_CANDIDATE")
        self.assertTrue(result["passed"])
        self.assertEqual(result["violation_count"], 0)
        self.assertEqual(result["gate_results"]["benchmark_v1"]["false_positive"], 0)
        self.assertLessEqual(result["gate_results"]["mean_latency_ms"], 2.0)


if __name__ == "__main__":
    unittest.main()

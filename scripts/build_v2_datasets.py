"""Dataset Ingestion, Canonical Deduplication, Benchmark Segregation, and Partitioning for ML Benchmark v2.

Creates:
- data/processed/v2/xss_train_v2.csv
- data/processed/v2/xss_val_v2.csv
- data/processed/v2/benchmark_v2.csv
- data/processed/v2/provenance_manifest.json
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
import random
import sys
from typing import Any

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.v2_dataset_pipeline import (
    DatasetIngestionPipeline,
    NormalizedSample,
    canonicalize_payload,
    compute_canonical_hash,
)

V1_TEST_PATH = PROJECT_ROOT / "data" / "processed" / "xss_test.csv"
V1_TRAIN_PATH = PROJECT_ROOT / "data" / "processed" / "xss_train.csv"
STAGING_DIR = PROJECT_ROOT / "data" / "raw" / "v2_sources"
OUTPUT_DIR = PROJECT_ROOT / "data" / "processed" / "v2"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

RANDOM_SEED = 42


def load_v1_test_hashes() -> set[str]:
    """Load canonical hashes of all samples in frozen Benchmark v1."""
    hashes = set()
    with open(V1_TEST_PATH, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = row.get("text", "")
            if text:
                canon = canonicalize_payload(text)
                hashes.add(compute_canonical_hash(canon))
    return hashes


def build_and_partition() -> dict[str, Any]:
    print("Initializing V2 Ingestion Pipeline...")
    pipeline = DatasetIngestionPipeline()
    v1_test_hashes = load_v1_test_hashes()
    print(f"Loaded {len(v1_test_hashes)} canonical hashes from frozen Benchmark v1.")

    # 1. Ingest baseline V1 training set
    print("Ingesting base V1 training set...")
    pipeline.ingest_csv_file(
        V1_TRAIN_PATH,
        text_column="text",
        label_column="label",
        label_mapping={"0": 0, "1": 1},
        source="HTTPParams-V1-Train",
        license="Academic/Research (CSIC/HTTPParams)",
        url_reference="data/raw/httpparamsdataset/payload_train.csv",
    )
    print(f"Total samples after V1 train: {len(pipeline.samples)}")

    # 2. Ingest staged SecLists XSS collections
    print("Ingesting staged SecLists XSS collections...")
    for txt_file in STAGING_DIR.glob("seclists_*.txt"):
        count = pipeline.ingest_txt_file(
            txt_file,
            label=1,
            source=f"SecLists-{txt_file.stem}",
            license="MIT License",
            url_reference=f"https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/XSS/robot-friendly/{txt_file.name}",
        )
        print(f"  Ingested {count} records from {txt_file.name}")

    # 3. Ingest PayloadsAllTheThings
    patt_file = STAGING_DIR / "payloadsallthethings_xss.txt"
    if patt_file.exists():
        count = pipeline.ingest_txt_file(
            patt_file,
            label=1,
            source="PayloadsAllTheThings-XSS",
            license="MIT License",
            url_reference="https://github.com/swisskyrepo/PayloadsAllTheThings",
        )
        print(f"  Ingested {count} records from payloadsallthethings_xss.txt")

    # 4. Ingest Benign Technical Corpus
    benign_json = STAGING_DIR / "benign_technical_corpus.json"
    if benign_json.exists():
        count = pipeline.ingest_json_file(
            benign_json,
            text_key="text",
            label_key="label",
            label_mapping={"0": 0},
            source="Curated-Benign-Technical",
            id_key="source_id",
            license="CC0-1.0 (Public Domain)",
            url_reference="internal://xshield-benchmark-curation",
        )
        print(f"  Ingested {count} records from benign_technical_corpus.json")

    # 5. Extract unique primary samples
    all_unique = pipeline.get_unique_samples()
    print(f"\nTotal raw ingested: {len(pipeline.samples)}")
    print(f"Unique canonical samples before V1-overlap pruning: {len(all_unique)}")

    # 6. Strict guard against Benchmark v1 overlap
    leakage_removed = 0
    safe_samples: list[NormalizedSample] = []
    for s in all_unique:
        if s.canonical_hash in v1_test_hashes:
            leakage_removed += 1
        else:
            safe_samples.append(s)

    print(f"Pruned {leakage_removed} samples matching Benchmark v1 test hashes.")
    print(f"Zero-contamination candidate pool size: {len(safe_samples)}")

    # Group safe samples by class
    benign_samples = [s for s in safe_samples if s.label == 0]
    xss_samples = [s for s in safe_samples if s.label == 1]
    print(f"Available Safe Pool: {len(benign_samples)} Benign, {len(xss_samples)} XSS")

    # 7. Curate Benchmark V2
    # Benchmark V2 target: ~1,000 diverse XSS vectors and ~2,500 benign samples (including keyword-heavy technical samples)
    # Stratified split to ensure Benchmark V2 is completely held out from training!
    # Set seed for reproducible split
    rng = random.Random(RANDOM_SEED)
    rng.shuffle(benign_samples)
    rng.shuffle(xss_samples)

    # Benchmark v2 size: 800 XSS and 2,400 Benign (1:3 ratio, high challenge)
    n_v2_xss = min(800, int(len(xss_samples) * 0.20))
    n_v2_benign = min(2400, int(len(benign_samples) * 0.15))

    benchmark_v2_xss = xss_samples[:n_v2_xss]
    remaining_xss = xss_samples[n_v2_xss:]

    benchmark_v2_benign = benign_samples[:n_v2_benign]
    remaining_benign = benign_samples[n_v2_benign:]

    benchmark_v2_samples = benchmark_v2_xss + benchmark_v2_benign
    rng.shuffle(benchmark_v2_samples)
    print(f"\nConstructed Benchmark V2: {len(benchmark_v2_samples)} samples ({len(benchmark_v2_benign)} Benign, {len(benchmark_v2_xss)} XSS)")

    # 8. Partition Remaining into Train V2 (85%) and Validation V2 (15%)
    remaining_samples = remaining_benign + remaining_xss
    rem_texts = [s.text for s in remaining_samples]
    rem_labels = [s.label for s in remaining_samples]

    train_idx, val_idx = train_test_split(
        range(len(remaining_samples)),
        test_size=0.15,
        random_state=RANDOM_SEED,
        stratify=rem_labels,
    )

    train_v2_samples = [remaining_samples[i] for i in train_idx]
    val_v2_samples = [remaining_samples[i] for i in val_idx]

    # Save CSV files
    def save_csv(samples: list[NormalizedSample], target_path: Path) -> None:
        with open(target_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["text", "label", "source", "source_id"])
            for s in samples:
                writer.writerow([s.text, s.label, s.source, s.source_id])
        print(f"Saved {target_path.name}: {len(samples)} samples")

    save_csv(train_v2_samples, OUTPUT_DIR / "xss_train_v2.csv")
    save_csv(val_v2_samples, OUTPUT_DIR / "xss_val_v2.csv")
    save_csv(benchmark_v2_samples, OUTPUT_DIR / "benchmark_v2.csv")

    # 9. Verify Mutual Exclusivity and Zero Leakage
    train_hashes = {s.canonical_hash for s in train_v2_samples}
    val_hashes = {s.canonical_hash for s in val_v2_samples}
    v2_test_hashes = {s.canonical_hash for s in benchmark_v2_samples}

    assert len(train_hashes.intersection(v1_test_hashes)) == 0, "Train V2 leaked into Benchmark V1!"
    assert len(val_hashes.intersection(v1_test_hashes)) == 0, "Val V2 leaked into Benchmark V1!"
    assert len(v2_test_hashes.intersection(v1_test_hashes)) == 0, "Benchmark V2 leaked into Benchmark V1!"
    assert len(train_hashes.intersection(v2_test_hashes)) == 0, "Train V2 leaked into Benchmark V2!"
    assert len(val_hashes.intersection(v2_test_hashes)) == 0, "Val V2 leaked into Benchmark V2!"
    assert len(train_hashes.intersection(val_hashes)) == 0, "Train V2 leaked into Val V2!"

    print("\n[ALL ZERO-LEAKAGE ASSERTIONS PASSED]")
    print("  Train V2 intersect Benchmark V1 = 0")
    print("  Val V2 intersect Benchmark V1 = 0")
    print("  Benchmark V2 intersect Benchmark V1 = 0")
    print("  Train V2 intersect Benchmark V2 = 0")
    print("  Val V2 intersect Benchmark V2 = 0")
    print("  Train V2 intersect Val V2 = 0")

    # 10. Generate Provenance Manifest
    manifest = {
        "created_at": pd.Timestamp.now(tz="UTC").isoformat(),
        "random_seed": RANDOM_SEED,
        "dataset_composition": {
            "total_unique_safe_samples": len(safe_samples),
            "train_v2": {
                "total": len(train_v2_samples),
                "benign": sum(1 for s in train_v2_samples if s.label == 0),
                "xss": sum(1 for s in train_v2_samples if s.label == 1),
            },
            "val_v2": {
                "total": len(val_v2_samples),
                "benign": sum(1 for s in val_v2_samples if s.label == 0),
                "xss": sum(1 for s in val_v2_samples if s.label == 1),
            },
            "benchmark_v2": {
                "total": len(benchmark_v2_samples),
                "benign": sum(1 for s in benchmark_v2_samples if s.label == 0),
                "xss": sum(1 for s in benchmark_v2_samples if s.label == 1),
            },
            "frozen_benchmark_v1": {
                "total": 3967,
                "benign": 3861,
                "xss": 106,
                "status": "IMMUTABLE_FROZEN",
            },
        },
        "sources": pipeline.generate_manifest()["sources"],
        "licenses": pipeline.generate_manifest()["licenses"],
        "leakage_verification": {
            "v1_test_overlap_count": 0,
            "benchmark_v2_train_overlap_count": 0,
            "status": "VERIFIED_ZERO_CONTAMINATION",
        },
    }

    manifest_path = OUTPUT_DIR / "provenance_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Saved complete provenance manifest to {manifest_path}")

    return manifest


if __name__ == "__main__":
    build_and_partition()

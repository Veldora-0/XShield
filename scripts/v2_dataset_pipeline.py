"""Dataset Ingestion, Canonical Deduplication, and Provenance Pipeline for ML Benchmark v2.

This module provides scaffolding for the future Benchmark v2 workflow.
It does NOT train any models or download external data.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import urllib.parse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


@dataclass(frozen=True)
class NormalizedSample:
    """Normalized representation of a single security or benign sample."""

    text: str
    label: int  # 0 = Benign, 1 = XSS
    source: str
    source_id: str
    license: str
    url_reference: str
    ingested_at: str
    canonical_text: str
    canonical_hash: str
    duplicate_group: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def canonicalize_payload(text: str, *, safe_url_decode: bool = True) -> str:
    """Compute a canonical comparison string for duplicate detection and leakage prevention.

    Normalizations applied:
    1. Strip leading and trailing whitespace.
    2. Casefold (lowercase for case-insensitive equivalence).
    3. Collapse multiple spaces, tabs, and newlines into a single space.
    4. Safe URL-decoding: decodes percent-encoded bytes if valid UTF-8.
    """
    cleaned = str(text).strip()
    if safe_url_decode and "%" in cleaned:
        try:
            # Unquote only if it does not introduce decoding errors
            unquoted = urllib.parse.unquote(cleaned)
            cleaned = unquoted
        except Exception:
            pass

    cleaned = cleaned.casefold()
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def compute_canonical_hash(canonical_text: str) -> str:
    """Compute SHA-256 hash of the canonicalized text."""
    return hashlib.sha256(canonical_text.encode("utf-8")).hexdigest()


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_V1_TEST_PATH = PROJECT_ROOT / "data" / "processed" / "xss_test.csv"


class DatasetIngestionPipeline:
    """Modular ingestion and deduplication pipeline for building ML Benchmark v2."""

    def __init__(self) -> None:
        self.samples: list[NormalizedSample] = []
        self._seen_canonical_hashes: dict[str, str] = {}  # hash -> primary source_id
        self._duplicate_log: list[dict[str, Any]] = []

    def ingest_record(
        self,
        text: str,
        label: int,
        *,
        source: str,
        source_id: str,
        license: str = "Unspecified/Research",
        url_reference: str = "",
    ) -> NormalizedSample:
        """Normalize and register a single sample with provenance tracking."""
        cleaned_text = str(text).strip()
        if not cleaned_text:
            raise ValueError("Sample text cannot be empty.")
        if label not in {0, 1}:
            raise ValueError(f"Label must be 0 (Benign) or 1 (XSS), got: {label}")

        canonical = canonicalize_payload(cleaned_text)
        canonical_hash = compute_canonical_hash(canonical)
        ingested_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

        duplicate_group = None
        if canonical_hash in self._seen_canonical_hashes:
            primary_id = self._seen_canonical_hashes[canonical_hash]
            duplicate_group = f"dup-of-{primary_id}"
            self._duplicate_log.append(
                {
                    "source": source,
                    "source_id": source_id,
                    "primary_id": primary_id,
                    "canonical_hash": canonical_hash,
                    "action": "flagged_duplicate",
                }
            )
        else:
            self._seen_canonical_hashes[canonical_hash] = source_id

        sample = NormalizedSample(
            text=cleaned_text,
            label=int(label),
            source=source,
            source_id=source_id,
            license=license,
            url_reference=url_reference,
            ingested_at=ingested_at,
            canonical_text=canonical,
            canonical_hash=canonical_hash,
            duplicate_group=duplicate_group,
        )
        self.samples.append(sample)
        return sample

    def ingest_txt_file(
        self,
        file_path: Path | str,
        label: int,
        *,
        source: str,
        license: str = "Unspecified/Research",
        url_reference: str = "",
    ) -> int:
        """Ingest line-by-line from a text file, ignoring empty lines and comments."""
        path = Path(file_path)
        count = 0
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for idx, line in enumerate(f, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                self.ingest_record(
                    text=stripped,
                    label=label,
                    source=source,
                    source_id=f"{path.stem}-{idx}",
                    license=license,
                    url_reference=url_reference,
                )
                count += 1
        return count

    def ingest_csv_file(
        self,
        file_path: Path | str,
        *,
        text_column: str,
        label_column: str,
        label_mapping: Mapping[str, int],
        source: str,
        id_column: str | None = None,
        license: str = "Unspecified/Research",
        url_reference: str = "",
    ) -> int:
        """Ingest from a CSV file with explicit column and label mappings."""
        path = Path(file_path)
        count = 0
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader, 1):
                raw_text = row.get(text_column, "").strip()
                if not raw_text:
                    continue
                raw_label = str(row.get(label_column, "")).strip().casefold()
                if raw_label not in label_mapping:
                    continue
                label_val = label_mapping[raw_label]
                src_id = str(row.get(id_column)) if id_column and row.get(id_column) else f"{path.stem}-{idx}"

                self.ingest_record(
                    text=raw_text,
                    label=label_val,
                    source=source,
                    source_id=src_id,
                    license=license,
                    url_reference=url_reference,
                )
                count += 1
        return count

    def ingest_json_file(
        self,
        file_path: Path | str,
        *,
        text_key: str,
        label_key: str,
        label_mapping: Mapping[str, int],
        source: str,
        id_key: str | None = None,
        license: str = "Unspecified/Research",
        url_reference: str = "",
    ) -> int:
        """Ingest from a JSON file containing a list of objects."""
        path = Path(file_path)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("JSON file must contain a root-level list of objects.")

        count = 0
        for idx, item in enumerate(data, 1):
            if not isinstance(item, dict):
                continue
            raw_text = str(item.get(text_key, "")).strip()
            if not raw_text:
                continue
            raw_label = str(item.get(label_key, "")).strip().casefold()
            if raw_label not in label_mapping:
                continue
            label_val = label_mapping[raw_label]
            src_id = str(item.get(id_key)) if id_key and item.get(id_key) else f"{path.stem}-{idx}"

            self.ingest_record(
                text=raw_text,
                label=label_val,
                source=source,
                source_id=src_id,
                license=license,
                url_reference=url_reference,
            )
            count += 1
        return count

    def get_unique_samples(self) -> list[NormalizedSample]:
        """Return only primary, non-duplicate samples."""
        return [s for s in self.samples if s.duplicate_group is None]

    def verify_no_overlap_with_benchmark_v1(
        self,
        v1_test_path: Path | str = DEFAULT_V1_TEST_PATH,
    ) -> list[str]:
        """Verify that no candidate sample has canonical overlap with Benchmark v1.

        Returns a list of overlapping canonical texts (must be empty for valid split).
        """
        v1_path = Path(v1_test_path)
        if not v1_path.exists():
            return []

        v1_canonical_hashes: set[str] = set()
        with open(v1_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                t = row.get("text", "")
                if t:
                    v1_canonical_hashes.add(compute_canonical_hash(canonicalize_payload(t)))

        overlap = []
        for sample in self.samples:
            if sample.canonical_hash in v1_canonical_hashes:
                overlap.append(sample.text)
        return overlap

    def generate_manifest(self) -> dict[str, Any]:
        """Generate a complete statistical summary and provenance manifest."""
        total = len(self.samples)
        unique = len(self.get_unique_samples())
        duplicates = total - unique

        by_source: dict[str, dict[str, int]] = {}
        by_license: dict[str, int] = {}
        class_counts = {0: 0, 1: 0}

        for s in self.get_unique_samples():
            class_counts[s.label] += 1
            by_source.setdefault(s.source, {"benign": 0, "xss": 0, "total": 0})
            if s.label == 1:
                by_source[s.source]["xss"] += 1
            else:
                by_source[s.source]["benign"] += 1
            by_source[s.source]["total"] += 1
            by_license[s.license] = by_license.get(s.license, 0) + 1

        benign_pct = round((class_counts[0] / unique * 100), 2) if unique > 0 else 0
        xss_pct = round((class_counts[1] / unique * 100), 2) if unique > 0 else 0

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "total_ingested": total,
            "unique_samples": unique,
            "duplicate_samples_pruned": duplicates,
            "class_distribution": {
                "benign_count": class_counts[0],
                "xss_count": class_counts[1],
                "benign_percentage": benign_pct,
                "xss_percentage": xss_pct,
                "target_ratio": "80% Benign / 20% XSS",
            },
            "sources": by_source,
            "licenses": by_license,
            "duplicate_log_count": len(self._duplicate_log),
        }

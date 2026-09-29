import json
import re
from pathlib import Path

import pandas as pd


RANDOM_SEED = 42
TEST_SIZE = 0.20
SOURCE_PATH = Path("data/raw/httpparamsdataset/payload_full.csv")
PROCESSED_DIR = Path("data/processed")
PROCESSED_PATH = PROCESSED_DIR / "xss_dataset.csv"
TRAIN_PATH = PROCESSED_DIR / "xss_train.csv"
TEST_PATH = PROCESSED_DIR / "xss_test.csv"
REPORT_PATH = PROCESSED_DIR / "dataset_report.json"


def canonicalize_text(value: str) -> str:
    """Create a comparison-only form for duplicate and leakage checks."""
    return re.sub(r"\s+", " ", value.casefold()).strip()


def load_and_clean_source(path: Path) -> tuple[pd.DataFrame, dict]:
    source = pd.read_csv(path, encoding="utf-8")
    required_columns = {"payload", "attack_type", "label"}
    missing_columns = required_columns.difference(source.columns)
    if missing_columns:
        raise ValueError(f"Source is missing required columns: {sorted(missing_columns)}")

    source_rows = len(source)
    source_missing = int(source[["payload", "attack_type", "label"]].isna().any(axis=1).sum())

    cleaned = source.copy()
    cleaned["payload"] = cleaned["payload"].astype("string")
    cleaned["attack_type"] = cleaned["attack_type"].astype("string").str.strip().str.casefold()
    cleaned["label"] = cleaned["label"].astype("string").str.strip().str.casefold()

    valid_payload = cleaned["payload"].notna() & cleaned["payload"].str.strip().ne("")
    valid_labels = cleaned["attack_type"].isin({"norm", "xss"})
    cleaned = cleaned.loc[valid_payload & valid_labels].copy()

    exact_duplicates_removed = int(cleaned.duplicated().sum())
    cleaned = cleaned.drop_duplicates()

    cleaned["_canonical_text"] = cleaned["payload"].map(canonicalize_text)
    canonical_duplicates_removed = int(cleaned["_canonical_text"].duplicated().sum())
    cleaned = cleaned.drop_duplicates(subset=["_canonical_text"])

    result = pd.DataFrame(
        {
            "text": cleaned["payload"].astype(str),
            "label": cleaned["attack_type"].map({"norm": 0, "xss": 1}).astype(int),
        }
    )
    report = {
        "source_file": str(path),
        "source_rows": int(source_rows),
        "source_missing_records": source_missing,
        "source_duplicate_rows": int(source.duplicated().sum()),
        "source_label_counts": {
            str(key): int(value)
            for key, value in source["label"].value_counts(dropna=False).items()
        },
        "source_attack_type_counts": {
            str(key): int(value)
            for key, value in source["attack_type"].value_counts(dropna=False).items()
        },
        "unsupported_attack_records_excluded": int((valid_payload & ~valid_labels).sum()),
        "invalid_records_excluded": int((~valid_payload).sum()),
        "exact_duplicates_removed": exact_duplicates_removed,
        "canonical_duplicates_removed": canonical_duplicates_removed,
        "length_metadata_mismatches": int(
            (source["length"] != source["payload"].astype(str).str.len()).sum()
        ),
    }
    return result, report


def split_dataset(dataset: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    test = (
        dataset.groupby("label", group_keys=False)
        .sample(frac=TEST_SIZE, random_state=RANDOM_SEED)
        .sort_index()
    )
    train = dataset.drop(index=test.index).sort_index()
    train = train.sort_index().reset_index(drop=True)
    test = test.sort_index().reset_index(drop=True)

    train_keys = {canonicalize_text(value) for value in train["text"]}
    test_keys = {canonicalize_text(value) for value in test["text"]}
    overlap = train_keys.intersection(test_keys)
    if overlap:
        raise ValueError("Canonical text overlap found between train and test sets.")

    split_report = {
        "random_seed": RANDOM_SEED,
        "test_size": TEST_SIZE,
        "train_rows": int(len(train)),
        "test_rows": int(len(test)),
        "train_class_counts": {
            str(key): int(value) for key, value in train["label"].value_counts().sort_index().items()
        },
        "test_class_counts": {
            str(key): int(value) for key, value in test["label"].value_counts().sort_index().items()
        },
        "canonical_train_test_overlap": len(overlap),
    }
    return train, test, split_report


def main() -> None:
    dataset, report = load_and_clean_source(SOURCE_PATH)
    train, test, split_report = split_dataset(dataset)
    report.update(
        {
            "final_rows": int(len(dataset)),
            "final_class_counts": {
                str(key): int(value)
                for key, value in dataset["label"].value_counts().sort_index().items()
            },
            **split_report,
            "label_mapping": {"0": "BENIGN (source attack_type=norm)", "1": "XSS (source attack_type=xss)"},
            "excluded_attack_types": ["sqli", "cmdi", "path-traversal"],
            "leakage_check": (
                "Compared case-folded, whitespace-normalized text keys across splits; "
                "no exact normalized overlap was found."
            ),
        }
    )

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    dataset.to_csv(PROCESSED_PATH, index=False, encoding="utf-8")
    train.to_csv(TRAIN_PATH, index=False, encoding="utf-8")
    test.to_csv(TEST_PATH, index=False, encoding="utf-8")
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

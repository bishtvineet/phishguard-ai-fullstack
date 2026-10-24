import argparse
import csv
import json
import os
import sys
import random
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Ensure backend root is on sys.path for absolute imports
CURRENT_DIR = Path(__file__).resolve().parent
BACKEND_ROOT = CURRENT_DIR.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.detectors.url.url_utils import ParsedURLComponents, validate_and_normalize_url
from app.ml.features import extract_lexical_features

DEFAULT_RAW_PATH = BACKEND_ROOT / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
DEFAULT_PROCESSED_DIR = BACKEND_ROOT / "data" / "processed"


def derive_group_key(components: ParsedURLComponents) -> str:
    """Derives a collision-safe grouping key. Never returns empty or generic keys."""
    if components.is_ip:
        clean_ip = components.hostname.strip("[]").lower()
        return f"ip:{clean_ip}"
    if components.registered_domain and components.suffix:
        return f"domain:{components.registered_domain.lower()}"
    if components.hostname:
        return f"host:{components.hostname.lower()}"
    return f"netloc:{components.netloc.lower()}"


class CleanRecord:
    __slots__ = ("raw_url", "normalized_url", "target_label", "group_key")

    def __init__(self, raw_url: str, normalized_url: str, target_label: int, group_key: str):
        self.raw_url = raw_url
        self.normalized_url = normalized_url
        self.target_label = target_label
        self.group_key = group_key


def parse_and_clean_dataset(
    csv_path: Path,
) -> Tuple[List[CleanRecord], Dict[str, int]]:
    """Reads raw CSV, validates columns and label values, normalizes, and drops conflicts."""
    if not csv_path.exists():
        raise FileNotFoundError(f"Source dataset not found at expected path: {csv_path}")

    stats = {
        "raw_records_read": 0,
        "dropped_missing_values": 0,
        "dropped_malformed_urls": 0,
        "dropped_exact_duplicates": 0,
        "dropped_label_conflicts": 0,
    }

    # First pass: read and validate URL syntax + labels
    url_to_labels: Dict[str, Set[int]] = defaultdict(set)
    url_to_components: Dict[str, Tuple[str, ParsedURLComponents]] = {}

    with open(csv_path, mode="r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "URL" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError("Input CSV must contain both 'URL' and 'label' header columns.")

        for row in reader:
            stats["raw_records_read"] += 1
            raw_url = row.get("URL")
            raw_label = row.get("label")

            if raw_url is None or raw_label is None:
                stats["dropped_missing_values"] += 1
                continue

            raw_url = raw_url.strip()
            raw_label = raw_label.strip()

            if not raw_url or raw_label not in ("0", "1"):
                stats["dropped_missing_values"] += 1
                continue

            # Validate structural validity and extract features
            feat = extract_lexical_features(raw_url)
            if feat is None:
                stats["dropped_malformed_urls"] += 1
                continue

            components, is_malformed = validate_and_normalize_url(raw_url)
            if is_malformed or components is None:
                stats["dropped_malformed_urls"] += 1
                continue

            norm_url = components.normalized_url
            # Map labels: 0 -> 1 (Phishing), 1 -> 0 (Legitimate)
            target = 1 - int(raw_label)

            url_to_labels[norm_url].add(target)
            if norm_url not in url_to_components:
                url_to_components[norm_url] = (raw_url, components)

    # Second pass: detect duplicates, purge label conflicts, build clean records
    clean_records: List[CleanRecord] = []
    for norm_url, labels in url_to_labels.items():
        if len(labels) > 1:
            stats["dropped_label_conflicts"] += 1
            continue

        target = next(iter(labels))
        raw_url, components = url_to_components[norm_url]
        group_key = derive_group_key(components)
        clean_records.append(CleanRecord(raw_url, norm_url, target, group_key))

    # Calculate exact duplicates
    total_valid = stats["raw_records_read"] - stats["dropped_missing_values"] - stats["dropped_malformed_urls"]
    stats["dropped_exact_duplicates"] = max(0, total_valid - len(url_to_labels))

    return clean_records, stats

def allocate_domain_groups(
    records: List[CleanRecord],
    max_urls: Optional[int] = 25000,
    seed: int = 42,
) -> Tuple[List[CleanRecord], List[CleanRecord], List[CleanRecord]]:
    """Deterministically allocates whole domain groups into train, validation, and test partitions."""
    # Group records by domain group key
    groups: Dict[str, List[CleanRecord]] = defaultdict(list)
    for r in records:
        groups[r.group_key].append(r)

    # Sort groups deterministically by key first
    all_group_keys = sorted(groups.keys())

    # Deterministically shuffle group order to ensure diverse domain sampling
    rng = random.Random(seed)
    rng.shuffle(all_group_keys)

    # Subsample domain groups if max_urls is specified
    selected_groups: List[Tuple[str, List[CleanRecord]]] = []
    accumulated_urls = 0

    if max_urls is not None and max_urls > 0:
        for grp_key in all_group_keys:
            grp_records = groups[grp_key]
            selected_groups.append((grp_key, grp_records))
            accumulated_urls += len(grp_records)
            if accumulated_urls >= max_urls:
                break
    else:
        selected_groups = [(k, groups[k]) for k in all_group_keys]

    target_ratios = {"train": 0.70, "val": 0.15, "test": 0.15}
    total_selected = sum(len(grp[1]) for grp in selected_groups)
    target_counts = {part: total_selected * target_ratios[part] for part in target_ratios}

    partition_records: Dict[str, List[CleanRecord]] = {"train": [], "val": [], "test": []}
    partition_phish: Dict[str, int] = {"train": 0, "val": 0, "test": 0}

    # Greedy allocation: assign group to the partition with highest proportional deficit
    for grp_key, grp_recs in selected_groups:
        grp_len = len(grp_recs)
        grp_p = sum(1 for r in grp_recs if r.target_label == 1)

        best_part = None
        highest_deficit = -float("inf")

        for part in ("train", "val", "test"):
            current_len = len(partition_records[part])
            # Deficit ratio: how far below its target count is this partition
            # A higher deficit means the partition needs data most urgently
            deficit = (target_counts[part] - current_len) / max(1.0, target_counts[part])

            # Secondary balance adjustment (slight penalty if class imbalance diverges from 0.50)
            new_len = current_len + grp_len
            new_p = partition_phish[part] + grp_p
            balance_divergence = abs((new_p / max(1, new_len)) - 0.50)

            score = deficit - (balance_divergence * 0.1)

            if score > highest_deficit:
                highest_deficit = score
                best_part = part

        partition_records[best_part].extend(grp_recs)
        partition_phish[best_part] += grp_p

    return partition_records["train"], partition_records["val"], partition_records["test"]


def write_partition_csv(file_path: Path, records: List[CleanRecord]) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "normalized_url", "label", "domain_group"])
        for r in records:
            writer.writerow([r.raw_url, r.normalized_url, r.target_label, r.group_key])


def prepare_dataset_pipeline(
    raw_csv: Path = DEFAULT_RAW_PATH,
    output_dir: Path = DEFAULT_PROCESSED_DIR,
    max_urls: Optional[int] = 25000,
    seed: int = 42,
) -> Dict:
    """Orchestrates dataset parsing, cleaning, group allocation, export, and metadata generation."""
    clean_records, cleaning_stats = parse_and_clean_dataset(raw_csv)
    train_recs, val_recs, test_recs = allocate_domain_groups(clean_records, max_urls=max_urls, seed=seed)

    # Invariant assertion: zero domain group overlap
    train_groups = {r.group_key for r in train_recs}
    val_groups = {r.group_key for r in val_recs}
    test_groups = {r.group_key for r in test_recs}

    assert train_groups.isdisjoint(val_groups), "Domain leakage detected between train and val!"
    assert train_groups.isdisjoint(test_groups), "Domain leakage detected between train and test!"
    assert val_groups.isdisjoint(test_groups), "Domain leakage detected between val and test!"

    output_dir.mkdir(parents=True, exist_ok=True)
    write_partition_csv(output_dir / "train.csv", train_recs)
    write_partition_csv(output_dir / "val.csv", val_recs)
    write_partition_csv(output_dir / "test.csv", test_recs)

    def split_summary(recs: List[CleanRecord], groups: Set[str]) -> Dict:
        phish = sum(1 for r in recs if r.target_label == 1)
        legit = len(recs) - phish
        return {
            "url_count": len(recs),
            "domain_group_count": len(groups),
            "phishing_count": phish,
            "legitimate_count": legit,
            "phishing_ratio": round(phish / max(1, len(recs)), 4),
        }

    metadata = {
        "source_dataset_id": "UCI_PhiUSIIL_Phishing_URL_Dataset (ID 967)",
        "execution_timestamp": datetime.now(timezone.utc).isoformat(),
        "random_seed": seed,
        "max_urls_parameter": max_urls,
        "actual_urls_processed": len(train_recs) + len(val_recs) + len(test_recs),
        "cleaning_statistics": {
            **cleaning_stats,
            "retained_clean_records": len(clean_records),
            "total_unique_domain_groups": len({r.group_key for r in clean_records}),
        },
        "splits": {
            "train": split_summary(train_recs, train_groups),
            "val": split_summary(val_recs, val_groups),
            "test": split_summary(test_recs, test_groups),
        },
    }

    with open(output_dir / "metadata.json", mode="w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return metadata


def main():
    parser = argparse.ArgumentParser(description="Prepare and split PhiUSIIL phishing URL dataset.")
    parser.add_argument("--raw-csv", type=Path, default=DEFAULT_RAW_PATH, help="Path to raw PhiUSIIL CSV file")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_PROCESSED_DIR, help="Output directory for processed CSVs")
    parser.add_argument("--max-urls", type=int, default=25000, help="Maximum approximate URLs to include (default: 25000)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic allocation")

    args = parser.parse_args()

    try:
        print(f"[INFO] Preparing dataset from {args.raw_csv} ...")
        meta = prepare_dataset_pipeline(
            raw_csv=args.raw_csv,
            output_dir=args.output_dir,
            max_urls=args.max_urls,
            seed=args.seed,
        )
        print("[SUCCESS] Dataset successfully prepared and split:")
        print(f"  Train: {meta['splits']['train']['url_count']} URLs across {meta['splits']['train']['domain_group_count']} groups")
        print(f"  Val:   {meta['splits']['val']['url_count']} URLs across {meta['splits']['val']['domain_group_count']} groups")
        print(f"  Test:  {meta['splits']['test']['url_count']} URLs across {meta['splits']['test']['domain_group_count']} groups")
        print(f"  Metadata saved to: {args.output_dir / 'metadata.json'}")
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
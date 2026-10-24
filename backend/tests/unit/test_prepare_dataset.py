import csv
import json
import pytest
from pathlib import Path

from scripts.prepare_dataset import (
    CleanRecord,
    allocate_domain_groups,
    derive_group_key,
    parse_and_clean_dataset,
    prepare_dataset_pipeline,
)
from app.detectors.url.url_utils import validate_and_normalize_url


def test_derive_group_key_collision_safety():
    # IP literal host
    comp_ip, _ = validate_and_normalize_url("http://192.168.1.1:8080/login")
    assert derive_group_key(comp_ip) == "ip:192.168.1.1"

    # Registered domain
    comp_domain, _ = validate_and_normalize_url("https://sub.portal.paypal.com/auth")
    assert derive_group_key(comp_domain) == "domain:paypal.com"

    # Bare hostname
    comp_bare, _ = validate_and_normalize_url("http://localhost/path")
    assert derive_group_key(comp_bare) == "host:localhost"


def test_parse_and_clean_dataset_removes_invalid_and_conflicts(tmp_path: Path):
    sample_csv = tmp_path / "sample.csv"
    sample_csv.write_text(
        "URL,label\n"
        "https://clean1.com/login,1\n"         # Legitimate -> target 0
        "https://phish1.com/account,0\n"       # Phishing -> target 1
        "https://conflict.com/test,0\n"        # Conflicting label
        "https://conflict.com/test,1\n"        # Conflicting label (both dropped)
        "javascript:alert(1),0\n"              # Malformed (dropped)
        "https://clean1.com/login,1\n",        # Duplicate (dropped)
        encoding="utf-8",
    )

    records, stats = parse_and_clean_dataset(sample_csv)

    urls = [r.normalized_url for r in records]
    assert "https://clean1.com/login" in urls
    assert "https://phish1.com/account" in urls
    assert "https://conflict.com/test" not in urls
    assert len(records) == 2

    # Check label mapping: raw 1 -> target 0; raw 0 -> target 1
    r_clean = next(r for r in records if r.normalized_url == "https://clean1.com/login")
    r_phish = next(r for r in records if r.normalized_url == "https://phish1.com/account")
    assert r_clean.target_label == 0
    assert r_phish.target_label == 1
    assert stats["dropped_label_conflicts"] == 1
    assert stats["dropped_malformed_urls"] == 1


def test_parse_and_clean_dataset_missing_columns_raises_error(tmp_path: Path):
    bad_csv = tmp_path / "bad.csv"
    bad_csv.write_text("wrong_col,label\nhttps://test.com,0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Input CSV must contain both 'URL' and 'label'"):
        parse_and_clean_dataset(bad_csv)


def test_domain_disjoint_allocation_preserves_zero_overlap():
    records = []
    # 30 domains with 4 URLs each
    for d_idx in range(30):
        domain = f"domain{d_idx}.com"
        for u_idx in range(4):
            records.append(
                CleanRecord(
                    raw_url=f"https://{domain}/path{u_idx}",
                    normalized_url=f"https://{domain}/path{u_idx}",
                    target_label=d_idx % 2,
                    group_key=f"domain:{domain}",
                )
            )

    train_recs, val_recs, test_recs = allocate_domain_groups(records, max_urls=None)

    train_groups = {r.group_key for r in train_recs}
    val_groups = {r.group_key for r in val_recs}
    test_groups = {r.group_key for r in test_recs}

    assert train_groups.isdisjoint(val_groups)
    assert train_groups.isdisjoint(test_groups)
    assert val_groups.isdisjoint(test_groups)
    assert len(train_recs) + len(val_recs) + len(test_recs) == len(records)


def test_prepare_dataset_pipeline_end_to_end_with_metadata(tmp_path: Path):
    raw_csv = tmp_path / "raw.csv"
    raw_csv.write_text(
        "URL,label\n"
        "https://d1.com/1,0\n"
        "https://d1.com/2,0\n"
        "https://d2.com/1,1\n"
        "https://d2.com/2,1\n"
        "https://d3.com/1,0\n"
        "https://d4.com/1,1\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "processed"

    meta = prepare_dataset_pipeline(raw_csv=raw_csv, output_dir=out_dir, max_urls=10)

    assert (out_dir / "train.csv").exists()
    assert (out_dir / "val.csv").exists()
    assert (out_dir / "test.csv").exists()
    assert (out_dir / "metadata.json").exists()

    with open(out_dir / "metadata.json", "r", encoding="utf-8") as f:
        meta_loaded = json.load(f)

    assert meta_loaded["source_dataset_id"] == "UCI_PhiUSIIL_Phishing_URL_Dataset (ID 967)"
    assert meta_loaded["actual_urls_processed"] == 6
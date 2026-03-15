"""
validate_dataset.py
===================
Validates the generated dataset for:
  - Expected file counts (≥700 generated, ≥300 historical)
  - Every .sol file having a paired .json metadata file
  - Required metadata fields present
  - Solidity files non-empty and containing a 'contract' keyword
  - Unique contract IDs

Usage
-----
    python scripts/validate_dataset.py

Exits with code 0 on success, 1 on failure.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT      = Path(__file__).resolve().parent.parent
GEN_CONTRACTS  = REPO_ROOT / "contracts" / "generated"
HIST_CONTRACTS = REPO_ROOT / "contracts" / "historical"
GEN_META       = REPO_ROOT / "metadata"  / "generated"
HIST_META      = REPO_ROOT / "metadata"  / "historical"
DATASET_INDEX  = REPO_ROOT / "dataset"   / "dataset_index.json"

REQUIRED_META_FIELDS = [
    "contract_id",
    "collection_source",
    "compiler_version",
    "protocol_type",
    "deployment_date",
    "exploit_history",
    "vulnerability_labels",
]

ERRORS: list[str] = []
WARNINGS: list[str] = []


def err(msg: str) -> None:
    ERRORS.append(msg)
    print(f"  ERROR: {msg}")


def warn(msg: str) -> None:
    WARNINGS.append(msg)
    print(f"  WARN : {msg}")


def ok(msg: str) -> None:
    print(f"  OK   : {msg}")


# ---------------------------------------------------------------------------
def check_file_counts() -> None:
    print("\n[1] File counts")
    gen_sol  = list(GEN_CONTRACTS.rglob("*.sol"))
    hist_sol = list(HIST_CONTRACTS.glob("*.sol"))
    gen_meta = list(GEN_META.rglob("*.json"))
    hist_meta = list(HIST_META.glob("*.json"))

    if len(gen_sol) >= 700:
        ok(f"Generated .sol files: {len(gen_sol)} (≥700)")
    else:
        err(f"Generated .sol files: {len(gen_sol)} (<700)")

    if len(hist_sol) >= 300:
        ok(f"Historical .sol files: {len(hist_sol)} (≥300)")
    else:
        err(f"Historical .sol files: {len(hist_sol)} (<300)")

    if len(gen_sol) == len(gen_meta):
        ok(f"Generated sol/json pairs balanced: {len(gen_sol)}")
    else:
        err(f"Mismatch generated: {len(gen_sol)} .sol vs {len(gen_meta)} .json")

    if len(hist_sol) == len(hist_meta):
        ok(f"Historical sol/json pairs balanced: {len(hist_sol)}")
    else:
        err(f"Mismatch historical: {len(hist_sol)} .sol vs {len(hist_meta)} .json")

    total = len(gen_sol) + len(hist_sol)
    if total >= 1000:
        ok(f"Total contracts: {total} (≥1000)")
    else:
        err(f"Total contracts: {total} (<1000)")


# ---------------------------------------------------------------------------
def check_sol_content() -> None:
    print("\n[2] Solidity file content")
    all_sol = list(GEN_CONTRACTS.rglob("*.sol")) + list(HIST_CONTRACTS.glob("*.sol"))
    empty = 0
    no_contract = 0
    for p in all_sol:
        content = p.read_text(encoding="utf-8", errors="replace")
        if len(content.strip()) == 0:
            empty += 1
        elif "contract " not in content:
            no_contract += 1

    if empty == 0:
        ok("No empty .sol files")
    else:
        err(f"{empty} empty .sol files found")

    if no_contract == 0:
        ok("All .sol files contain 'contract' keyword")
    else:
        warn(f"{no_contract} .sol files missing 'contract' keyword")


# ---------------------------------------------------------------------------
def check_metadata_fields() -> None:
    print("\n[3] Metadata required fields")
    all_meta = (
        list(GEN_META.rglob("*.json")) + list(HIST_META.glob("*.json"))
    )
    missing_fields: dict[str, int] = {}
    invalid_json = 0

    for p in all_meta:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            invalid_json += 1
            continue
        for field in REQUIRED_META_FIELDS:
            if field not in data:
                missing_fields[field] = missing_fields.get(field, 0) + 1

    if invalid_json == 0:
        ok("All metadata files are valid JSON")
    else:
        err(f"{invalid_json} metadata files have invalid JSON")

    if not missing_fields:
        ok("All required metadata fields present")
    else:
        for field, count in missing_fields.items():
            err(f"Field '{field}' missing in {count} metadata files")


# ---------------------------------------------------------------------------
def check_unique_contract_ids() -> None:
    print("\n[4] Unique contract IDs")
    all_meta = (
        list(GEN_META.rglob("*.json")) + list(HIST_META.glob("*.json"))
    )
    seen: set[str] = set()
    dupes = 0
    for p in all_meta:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        cid = data.get("contract_id", "")
        if cid in seen:
            dupes += 1
        seen.add(cid)

    if dupes == 0:
        ok(f"All {len(seen)} contract IDs are unique")
    else:
        warn(f"{dupes} duplicate contract IDs found (hash collision in generation)")


# ---------------------------------------------------------------------------
def check_dataset_index() -> None:
    print("\n[5] Dataset index")
    if not DATASET_INDEX.exists():
        err("dataset/dataset_index.json not found")
        return
    try:
        index = json.loads(DATASET_INDEX.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        err("dataset/dataset_index.json is not valid JSON")
        return

    for key in ("dataset_name", "version", "stats", "records"):
        if key not in index:
            err(f"dataset_index.json missing key '{key}'")
        else:
            ok(f"dataset_index.json has '{key}'")

    total = index.get("stats", {}).get("total", 0)
    if total >= 1000:
        ok(f"Index reports {total} records (≥1000)")
    else:
        err(f"Index reports only {total} records (<1000)")


# ---------------------------------------------------------------------------
def check_subtype_coverage() -> None:
    print("\n[6] Subtype coverage")
    expected_subtypes = {
        "block_timestamp_manipulation",
        "deadline_bypass",
        "block_number_manipulation",
        "time_window_attack",
        "timestamp_overflow",
        "vesting_schedule_manipulation",
        "miner_scheduled_execution",
    }

    found: set[str] = set()
    for d in GEN_CONTRACTS.iterdir():
        if d.is_dir():
            found.add(d.name)

    missing = expected_subtypes - found
    if not missing:
        ok(f"All {len(expected_subtypes)} subtypes have generated contract directories")
    else:
        for sub in sorted(missing):
            err(f"Subtype directory missing: {sub}")


# ---------------------------------------------------------------------------
def main() -> None:
    print("=" * 60)
    print("Timestamp Dependence Dataset Validator")
    print("=" * 60)

    check_file_counts()
    check_sol_content()
    check_metadata_fields()
    check_unique_contract_ids()
    check_dataset_index()
    check_subtype_coverage()

    print("\n" + "=" * 60)
    if ERRORS:
        print(f"RESULT: FAILED  ({len(ERRORS)} error(s), {len(WARNINGS)} warning(s))")
        for e in ERRORS:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print(f"RESULT: PASSED  (0 errors, {len(WARNINGS)} warning(s))")
    print("=" * 60)


if __name__ == "__main__":
    main()

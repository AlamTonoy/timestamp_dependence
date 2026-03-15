"""
build_dataset.py
================
Orchestrates the full dataset build:
  1. Generates 700 AI-generated Solidity contracts (100 per subtype).
  2. Collects 300 historically-inspired contracts.
  3. Assembles a single dataset_index.json catalogue in dataset/.

Usage
-----
    python scripts/build_dataset.py

The script is idempotent: running it again overwrites existing files.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running from any directory
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scripts.generate_contracts import generate  # noqa: E402
from scripts.collect_historical  import collect   # noqa: E402

DATASET_DIR = REPO_ROOT / "dataset"
DATASET_DIR.mkdir(exist_ok=True)

GEN_CONTRACTS  = REPO_ROOT / "contracts" / "generated"
HIST_CONTRACTS = REPO_ROOT / "contracts" / "historical"
GEN_META       = REPO_ROOT / "metadata"  / "generated"
HIST_META      = REPO_ROOT / "metadata"  / "historical"

TARGET_GENERATED   = 700   # 100 per subtype × 7 subtypes
TARGET_HISTORICAL  = 300


def _load_all_metadata() -> list[dict]:
    records = []

    # Generated
    for meta_path in sorted(GEN_META.rglob("*.json")):
        subtype = meta_path.parent.name
        sol_rel = (
            REPO_ROOT / "contracts" / "generated" / subtype / (meta_path.stem + ".sol")
        )
        entry = json.loads(meta_path.read_text(encoding="utf-8"))
        entry["_source"]       = "generated"
        entry["_sol_path"]     = str(sol_rel.relative_to(REPO_ROOT))
        entry["_meta_path"]    = str(meta_path.relative_to(REPO_ROOT))
        records.append(entry)

    # Historical
    for meta_path in sorted(HIST_META.glob("*.json")):
        sol_rel = HIST_CONTRACTS / (meta_path.stem + ".sol")
        entry = json.loads(meta_path.read_text(encoding="utf-8"))
        entry["_source"]    = "historical"
        entry["_sol_path"]  = str(sol_rel.relative_to(REPO_ROOT))
        entry["_meta_path"] = str(meta_path.relative_to(REPO_ROOT))
        records.append(entry)

    return records


def _build_stats(records: list[dict]) -> dict:
    subtypes: dict[str, int] = {}
    severities: dict[str, int] = {}
    sources: dict[str, int] = {}
    exploited = 0

    for r in records:
        src = r.get("_source", "unknown")
        sources[src] = sources.get(src, 0) + 1

        labels = r.get("vulnerability_labels", {})
        for label_val in labels.values():
            sub = label_val.get("subtype", "unknown")
            sev = label_val.get("severity", "unknown")
            subtypes[sub]   = subtypes.get(sub, 0) + 1
            severities[sev] = severities.get(sev, 0) + 1

        if r.get("exploit_history", {}).get("exploited"):
            exploited += 1

    return {
        "total":      len(records),
        "sources":    sources,
        "subtypes":   subtypes,
        "severities": severities,
        "exploited":  exploited,
    }


def build() -> None:
    print("=" * 60)
    print("Step 1/2  Generating AI contracts …")
    generate(contracts_per_subtype=TARGET_GENERATED // 7)

    print("=" * 60)
    print("Step 2/2  Collecting historical contracts …")
    collect(target=TARGET_HISTORICAL)

    print("=" * 60)
    print("Assembling dataset index …")
    records = _load_all_metadata()
    stats   = _build_stats(records)

    index = {
        "dataset_name":    "Timestamp Dependence Smart Contract Dataset",
        "version":         "1.0.0",
        "description": (
            "1000 Solidity smart contracts containing Timestamp Dependence "
            "vulnerabilities (SWC-116). ~700 AI-generated across 7 subtypes; "
            "~300 based on historical attack patterns."
        ),
        "stats":   stats,
        "records": records,
    }

    index_path = DATASET_DIR / "dataset_index.json"
    index_path.write_text(
        json.dumps(index, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"\nDataset index written to {index_path.relative_to(REPO_ROOT)}")
    print(f"  Total contracts : {stats['total']}")
    print(f"  Sources         : {stats['sources']}")
    print(f"  Subtypes        : {stats['subtypes']}")
    print(f"  Severities      : {stats['severities']}")
    print(f"  Exploited       : {stats['exploited']}")
    print("=" * 60)
    print("Build complete.")


if __name__ == "__main__":
    build()

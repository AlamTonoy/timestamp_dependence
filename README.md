# Timestamp Dependence — Smart Contract Vulnerability Dataset

A curated dataset of **1 000 Solidity smart contracts** each containing a
[Timestamp Dependence (SWC-116)](https://swcregistry.io/docs/SWC-116) vulnerability,
intended for training and evaluating smart-contract vulnerability-detection models.

---

## Dataset at a glance

| Split | Count | Source |
|-------|------:|--------|
| AI-generated | 700 | Synthetic, covers all 7 subtypes |
| Historical | 300 | Based on real-world attack patterns |
| **Total** | **1 000** | |

Every contract is paired with a structured **vulnerability-feedback JSON** file
(see [Metadata format](#metadata-format)) that records compiler version, protocol
type, exploit history, CWE/SWC labels, and more.

---

## Repository layout

```
.
├── taxonomy.py                          # Full TIMESTAMP_DEPENDENCE_TAXONOMY definition
├── requirements.txt                     # Python deps
├── scripts/
│   ├── generate_contracts.py            # Generates 700 AI contracts (100/subtype)
│   ├── collect_historical.py            # Produces 300 historical contracts
│   ├── build_dataset.py                 # Orchestrates full build → dataset_index.json
│   └── validate_dataset.py              # Validates counts, content, and metadata
├── contracts/
│   ├── generated/
│   │   ├── block_timestamp_manipulation/  contract_001.sol … contract_100.sol
│   │   ├── deadline_bypass/
│   │   ├── block_number_manipulation/
│   │   ├── time_window_attack/
│   │   ├── timestamp_overflow/
│   │   ├── vesting_schedule_manipulation/
│   │   └── miner_scheduled_execution/
│   └── historical/                      contract_h001.sol … contract_h300.sol
├── metadata/
│   ├── generated/<subtype>/             contract_001.json … contract_100.json
│   └── historical/                      contract_h001.json … contract_h300.json
└── dataset/
    └── dataset_index.json               # Master index: all 1 000 records
```

---

## Vulnerability subtypes

The taxonomy (`taxonomy.py`) defines **7 subtypes** of Timestamp Dependence:

| Subtype ID | Canonical Name | Severity | CWE | SWC |
|------------|---------------|----------|-----|-----|
| `block_timestamp_manipulation` | Block Timestamp Manipulation | medium | CWE-829, CWE-330 | SWC-116 |
| `deadline_bypass` | Deadline/Expiry Bypass | high | CWE-829 | SWC-116 |
| `block_number_manipulation` | Block Number Dependency | medium | CWE-829 | SWC-116 |
| `time_window_attack` | Time Window Attack | medium | CWE-362 | SWC-116 |
| `timestamp_overflow` | Timestamp Overflow | low | CWE-190 | SWC-116, SWC-101 |
| `vesting_schedule_manipulation` | Vesting Schedule Manipulation | high | CWE-829 | SWC-116 |
| `miner_scheduled_execution` | Miner-Manipulated Scheduled Executions | medium | CWE-829 | SWC-116 |

---

## Metadata format

Each contract has a companion `.json` file in `metadata/` with the following schema:

```jsonc
{
  "contract_id":           "0x...",          // fake address (dataset identifier)
  "collection_source":     "ai_generated",   // or "historical_attack_pattern"
  "compiler_version":      "0.8.19",
  "solidity_version":      "^0.8.0",
  "optimization_enabled":  true,
  "optimization_runs":     200,
  "protocol_type":         "AMM",
  "protocol_name":         "AlphaSwap",
  "total_value_locked_usd": 5000000,
  "deployment_date":       "2024-03-15",
  "audit_status":          "Trail_of_Bits_2024",   // or null

  "exploit_history": {
    "exploited":           true,
    "exploit_date":        "2024-06-20",
    "exploit_value_usd":   1200000,
    "exploit_tx":          "0x..."
  },

  "vulnerability_labels": {
    "timestamp_dependence": {
      "present":      true,
      "subtype":      "block_timestamp_manipulation",
      "severity":     "medium",
      "confidence":   0.95,
      "line_numbers": [45, 67],
      "cwe":          ["CWE-829"],
      "swc":          ["SWC-116"]
    }
  }
}
```

---

## Quick start

### Rebuild the dataset from scratch

```bash
# regenerate all 1 000 contracts + metadata + index
python scripts/build_dataset.py
```

### Validate the dataset

```bash
python scripts/validate_dataset.py
```

Expected output ends with `RESULT: PASSED`.

### Run only one step

```bash
# 700 generated contracts only
python scripts/generate_contracts.py

# 300 historical contracts only
python scripts/collect_historical.py
```

---

## Historical attack reference

The 300 historical contracts are derived from patterns documented in public
post-mortems and security research for the following incidents (among others):

| Contract/Protocol | Year | Loss (USD) | Subtype |
|-------------------|------|------------|---------|
| GovernMental | 2016 | ~50 k | block_timestamp_manipulation |
| SmartBillions | 2017 | ~200 k | block_timestamp_manipulation |
| FoMo3D | 2018 | ~45 k | block_number_manipulation |
| EtherPot | 2018 | ~1 M | block_timestamp_manipulation |
| Compound Timelock pattern | 2020+ | — | miner_scheduled_execution |
| Badger DAO vesting | 2021 | ~800 k | vesting_schedule_manipulation |
| Cream Finance | 2021 | ~14 M | time_window_attack |
| Beanstalk Farms | 2022 | ~9.7 M | vesting_schedule_manipulation |
| Ronin Bridge | 2022 | ~625 M | time_window_attack |

> **Note**: The Solidity source files in `contracts/historical/` are
> **illustrative re-implementations** derived from publicly available
> post-mortems, not verbatim copies of deployed bytecode.

---

## Detection tools

The following tools detect SWC-116 / Timestamp Dependence:

| Tool | Detector ID |
|------|-------------|
| Slither | `timestamp`, `block-timestamp` |
| Mythril | `SWC-116` |
| Securify | `TODTimestamp` |
| SmartCheck | `SOLIDITY_BLOCK_TIMESTAMP` |
| 4nalyzer | `timestamp-dependence` |
| Aderyn | `block-timestamp-usage` |

---

## DASP classification

This dataset covers **DASP Top-10 #7 — Bad Randomness**, specifically the
Timestamp Dependence sub-class (mapping confidence: 1.0).

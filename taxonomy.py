"""
Timestamp Dependence Vulnerability Taxonomy
============================================
Defines the full classification hierarchy for timestamp-dependence
smart-contract vulnerabilities used to label the generated dataset.
"""

TIMESTAMP_DEPENDENCE_TAXONOMY = {
    "class_id": 3,
    "class_name": "Timestamp Dependence",
    "description": (
        "Vulnerabilities where block parameters are manipulated by "
        "validators/miners to alter contract logic."
    ),

    "subtypes": {

        "block_timestamp_manipulation": {
            "canonical_name": "Block Timestamp Manipulation",
            "aliases": [
                "block.timestamp Dependency",
                "now Keyword Vulnerability",
                "Miner Timestamp Control",
                "Time-Based Logic Flaw",
            ],
            "cwe_ids": ["CWE-829", "CWE-330"],
            "swc_ids": ["SWC-116"],
            "patterns": [
                r"block\.timestamp",
                r"\bnow\b",
                r"block\.number.*time",
            ],
            "keywords": [
                "block.timestamp", "now", "timestamp dependence",
                "miner manipulation", "time-based vulnerability",
                "block time abuse", "miner-influenced time",
                "predictable block time", "time-based logic",
            ],
            "severity": "medium",
        },

        "deadline_bypass": {
            "canonical_name": "Deadline/Expiry Bypass",
            "aliases": [
                "Timestamp Deadline Manipulation",
                "Expiry Time Attack",
                "Time Lock Bypass",
                "Auction Timing Abuse",
            ],
            "cwe_ids": ["CWE-829"],
            "swc_ids": ["SWC-116"],
            "keywords": [
                "deadline manipulation", "expiry bypass",
                "timestamp deadline", "time lock attack",
                "auction timing abuse", "time-based lock bypass",
            ],
            "severity": "high",
        },

        "block_number_manipulation": {
            "canonical_name": "Block Number Dependency",
            "aliases": [
                "block.number Vulnerability",
                "Block Height Manipulation",
                "Future Block Dependency",
            ],
            "cwe_ids": ["CWE-829"],
            "swc_ids": ["SWC-116"],
            "keywords": [
                "block.number", "block height",
                "block-based timing", "mining manipulation",
            ],
            "severity": "medium",
        },

        "time_window_attack": {
            "canonical_name": "Time Window Attack",
            "aliases": [
                "Timing Race Condition",
                "Temporal Logic Flaw",
                "Time-Sensitive Operation",
            ],
            "cwe_ids": ["CWE-362"],
            "swc_ids": ["SWC-116"],
            "keywords": [
                "time window", "timing attack", "temporal race",
                "time-sensitive logic", "timing race condition",
            ],
            "severity": "medium",
        },

        "timestamp_overflow": {
            "canonical_name": "Timestamp Overflow",
            "aliases": [
                "Year 2038 Problem",
                "Epoch Overflow",
                "uint32 Timestamp Limit",
            ],
            "cwe_ids": ["CWE-190"],
            "swc_ids": ["SWC-116", "SWC-101"],
            "keywords": [
                "timestamp overflow", "year 2038",
                "epoch overflow", "uint32 timestamp",
            ],
            "severity": "low",
        },

        "vesting_schedule_manipulation": {
            "canonical_name": "Vesting Schedule Manipulation",
            "aliases": [
                "Token Vesting Time Attack",
                "Cliff Period Bypass",
                "Vesting Acceleration",
            ],
            "cwe_ids": ["CWE-829"],
            "swc_ids": ["SWC-116"],
            "keywords": [
                "vesting manipulation", "vesting schedule",
                "cliff bypass", "vesting acceleration",
                "time-dependent price calculations",
            ],
            "severity": "high",
        },

        "miner_scheduled_execution": {
            "canonical_name": "Miner-Manipulated Scheduled Executions",
            "aliases": [
                "Validator Timestamp Gaming",
                "Block Producer Time Manipulation",
            ],
            "cwe_ids": ["CWE-829"],
            "swc_ids": ["SWC-116"],
            "keywords": [
                "miner-manipulated scheduled executions",
                "validator timestamp gaming",
                "15-second window", "block producer time",
            ],
            "severity": "medium",
        },
    },

    "related_patterns": [
        "if (block.timestamp > deadline)",
        "require(block.timestamp < expiry)",
        "lottery based on block.timestamp",
        "randomness from block.timestamp",
        "time-locked operations",
        "timestamp in require statements",
        "timestamp-based access control",
    ],

    "tools_detection": {
        "slither":    ["timestamp", "block-timestamp"],
        "mythril":    ["SWC-116"],
        "securify":   ["TODTimestamp"],
        "smartcheck": ["SOLIDITY_BLOCK_TIMESTAMP"],
        "4nalyzer":   ["timestamp-dependence"],
        "aderyn":     ["block-timestamp-usage"],
    },

    "dasp_id": "DASP-7",
    "mapping_confidence": 1.0,
}

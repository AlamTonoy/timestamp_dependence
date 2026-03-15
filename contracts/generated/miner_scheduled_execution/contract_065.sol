// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/// @title OmicronD - Batch Executor with Timestamp Guard
/// @notice VULNERABLE: batch window enforced by block.timestamp (SWC-116)
contract OmicronD {
    address public admin;
    uint256 public batchWindow = 3600;
    uint256 public lastBatch;

    struct Call {
        address target;
        bytes   data;
        uint256 value;
    }

    constructor() {
        admin = msg.sender;
        lastBatch = block.timestamp;
    }

    // VULN: validator includes this tx at a timestamp that opens the window
    function executeBatch(Call[] calldata calls) external {
        require(msg.sender == admin, "Not admin");
        require(
            block.timestamp >= lastBatch + batchWindow,
            "Window not open"
        );
        lastBatch = block.timestamp;
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok,) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            require(ok, "Call failed");
        }
    }
}

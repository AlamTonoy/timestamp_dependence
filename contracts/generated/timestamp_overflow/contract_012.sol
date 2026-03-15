// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

/// @title MuTwo - Cumulative Timestamp Overflow
/// @notice VULNERABLE: cumulative seconds can overflow uint32 (SWC-101)
contract MuTwo {
    uint32 public cumulativeTime;  // VULN: wraps after ~136 years total
    uint256 public lastUpdate;

    function tick() external {
        if (lastUpdate != 0) {
            // VULN: delta silently truncated then added to wrapping accumulator
            uint32 delta = uint32(block.timestamp - lastUpdate);
            cumulativeTime += delta;
        }
        lastUpdate = block.timestamp;
    }
}

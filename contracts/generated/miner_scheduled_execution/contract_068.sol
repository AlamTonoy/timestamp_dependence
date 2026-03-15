// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title SigmaG - Keeper-Based Job Scheduler
/// @notice VULNERABLE: job upkeep timing uses block.timestamp (SWC-116)
contract SigmaG {
    uint256 public lastRun;
    uint256 public interval = 86400;
    address public keeper;

    constructor(address _keeper) {
        keeper  = _keeper;
        lastRun = block.timestamp;
    }

    function checkUpkeep() external view returns (bool) {
        // VULN: miner sets block.timestamp to trigger upkeep prematurely
        return block.timestamp >= lastRun + interval;
    }

    function performUpkeep() external {
        require(msg.sender == keeper, "Not keeper");
        require(block.timestamp >= lastRun + interval, "Too soon");
        lastRun = block.timestamp;
        _doWork();
    }

    function _doWork() internal {
        // ... protocol maintenance work
    }
}

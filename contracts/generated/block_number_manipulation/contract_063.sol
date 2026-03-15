// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title NuB - Block-Based Rate Limiter
/// @notice VULNERABLE: rate limit window uses block.number (SWC-116)
contract NuB {
    mapping(address => uint256) public lastActionBlock;
    uint256 public cooldownBlocks = 1800;

    // VULN: miner can include own tx in a specific block to bypass cooldown
    function action() external {
        require(
            block.number >= lastActionBlock[msg.sender] + cooldownBlocks,
            "Cooldown active"
        );
        lastActionBlock[msg.sender] = block.number;
        // ... perform action
    }
}

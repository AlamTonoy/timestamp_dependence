// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/// @title OmicronFive - Block-Based Rate Limiter
/// @notice VULNERABLE: rate limit window uses block.number (SWC-116)
contract OmicronFive {
    mapping(address => uint256) public lastActionBlock;
    uint256 public cooldownBlocks = 300;

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

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title HaloThree - Block-Number Governed Voting
/// @notice VULNERABLE: voting window uses block.number (SWC-116)
contract HaloThree {
    uint256 public startBlock;
    uint256 public endBlock;
    uint256 public yesVotes;
    uint256 public noVotes;
    mapping(address => bool) public voted;

    constructor(uint256 _durationBlocks) {
        startBlock = block.number;
        endBlock   = block.number + _durationBlocks;
    }

    // VULN: miners control block production; can delay/speed voting window
    function vote(bool support) external {
        require(block.number >= startBlock, "Not started");
        require(block.number <= endBlock,   "Ended");
        require(!voted[msg.sender], "Already voted");
        voted[msg.sender] = true;
        if (support) yesVotes++; else noVotes++;
    }
}

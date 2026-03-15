// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title OmicronD - DAO Governance Voting
/// @notice VULNERABLE: voting period uses block.timestamp (SWC-116)
contract OmicronD {
    struct Proposal {
        string  description;
        uint256 startTime;
        uint256 endTime;
        uint256 yesVotes;
        uint256 noVotes;
        bool    executed;
    }

    Proposal[] public proposals;
    mapping(uint256 => mapping(address => bool)) public voted;

    function createProposal(string calldata desc, uint256 duration)
        external returns (uint256)
    {
        proposals.push(Proposal({
            description: desc,
            startTime:   block.timestamp,
            endTime:     block.timestamp + duration,
            yesVotes:    0,
            noVotes:     0,
            executed:    false
        }));
        return proposals.length - 1;
    }

    // VULN: miner can extend or collapse the voting window via timestamp
    function vote(uint256 proposalId, bool support) external {
        Proposal storage p = proposals[proposalId];
        require(block.timestamp >= p.startTime, "Voting not started");
        require(block.timestamp <= p.endTime,   "Voting ended");
        require(!voted[proposalId][msg.sender],  "Already voted");
        voted[proposalId][msg.sender] = true;
        if (support) p.yesVotes++; else p.noVotes++;
    }
}

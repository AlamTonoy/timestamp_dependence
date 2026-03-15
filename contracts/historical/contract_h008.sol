// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/// @title DAOVotingBlockDependence - Block-Number Based Voting
/// @notice Mirrors patterns seen in several DAO exploits (2020-2022).
contract DAOVotingBlockDependence {
    struct Proposal {
        bytes32 descriptionHash;
        uint256 startBlock;
        uint256 endBlock;
        uint256 forVotes;
        uint256 againstVotes;
    }

    Proposal[] public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    uint256 public votingDelay  = 1;    // blocks
    uint256 public votingPeriod = 17280; // ~3 days at 15s/block

    function propose(bytes32 descHash) external returns (uint256) {
        proposals.push(Proposal({
            descriptionHash: descHash,
            // VULN: miner can choose when to include this tx; start/end is known
            startBlock: block.number + votingDelay,
            endBlock:   block.number + votingDelay + votingPeriod,
            forVotes:     0,
            againstVotes: 0
        }));
        return proposals.length - 1;
    }

    function castVote(uint256 proposalId, bool support) external {
        Proposal storage p = proposals[proposalId];
        // VULN: block.number controlled by validator; window manipulable
        require(block.number >= p.startBlock, "Voting not started");
        require(block.number <= p.endBlock,   "Voting ended");
        require(!hasVoted[proposalId][msg.sender], "Already voted");
        hasVoted[proposalId][msg.sender] = true;
        if (support) p.forVotes++; else p.againstVotes++;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title BeanstalkFarmsVesting - Flash Governance Timestamp Exploit
/// @notice Mirrors the Beanstalk Farms April 2022 flash-governance attack pattern.
contract BeanstalkFarmsVestingPatched {
    struct Proposal {
        address proposer;
        bytes   callData;
        uint256 createdAt;
        uint256 passedAt;
        bool    executed;
    }

    Proposal[] public proposals;
    uint256 public votingPeriod  = 15 days;
    uint256 public executionDelay = 1 days;

    mapping(uint256 => mapping(address => uint256)) public votes;
    mapping(uint256 => uint256) public totalVotes;
    uint256 public quorum = 1e21; // simplified

    function propose(bytes calldata data) external returns (uint256) {
        proposals.push(Proposal({
            proposer:  msg.sender,
            callData:  data,
            // VULN: block.timestamp set by validator when tx is included
            createdAt: block.timestamp,
            passedAt:  0,
            executed:  false
        }));
        return proposals.length - 1;
    }

    function vote(uint256 pid, uint256 weight) external {
        Proposal storage p = proposals[pid];
        require(block.timestamp <= p.createdAt + votingPeriod, "Voting ended");
        votes[pid][msg.sender] += weight;
        totalVotes[pid]        += weight;
        if (totalVotes[pid] >= quorum && p.passedAt == 0) {
            // VULN: block.timestamp sets passedAt; validators can manipulate
            p.passedAt = block.timestamp;
        }
    }

    function execute(uint256 pid) external {
        Proposal storage p = proposals[pid];
        require(p.passedAt > 0, "Not passed");
        require(!p.executed, "Already executed");
        // VULN: executionDelay from passedAt can be collapsed by miner
        require(block.timestamp >= p.passedAt + executionDelay, "Delay active");
        p.executed = true;
        (bool ok,) = address(this).call(p.callData);
        require(ok);
    }
}

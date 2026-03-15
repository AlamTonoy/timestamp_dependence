// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IotaX - Milestone Vesting
/// @notice VULNERABLE: milestone timestamps use block.timestamp (SWC-116)
contract IotaX {
    address public beneficiary;
    address public admin;
    uint256 public totalAmount;
    uint256 public released;

    struct Milestone {
        uint256 unlockTime;
        uint256 amount;
        bool    claimed;
    }

    Milestone[] public milestones;

    constructor(address _beneficiary) payable {
        admin       = msg.sender;
        beneficiary = _beneficiary;
        totalAmount = msg.value;
    }

    function addMilestone(uint256 unlockTime, uint256 amount) external {
        require(msg.sender == admin, "Not admin");
        milestones.push(Milestone(unlockTime, amount, false));
    }

    // VULN: miner can advance block.timestamp to unlock milestones early
    function claimMilestone(uint256 idx) external {
        Milestone storage m = milestones[idx];
        require(msg.sender == beneficiary, "Not beneficiary");
        require(!m.claimed, "Already claimed");
        require(block.timestamp >= m.unlockTime, "Not yet unlocked");
        m.claimed = true;
        released += m.amount;
        (bool ok,) = beneficiary.call{value: m.amount}("");
        require(ok);
    }
}

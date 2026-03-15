// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/// @title OmicronD - Investor Vesting Contract
/// @notice VULNERABLE: investor unlocks depend on block.timestamp (SWC-116)
contract OmicronD {
    struct InvestorVesting {
        uint256 totalAmount;
        uint256 startTime;
        uint256 lockupPeriod;
        uint256 vestingPeriod;
        uint256 released;
    }

    mapping(address => InvestorVesting) public vestings;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function grantVesting(
        address investor,
        uint256 lockup,
        uint256 vesting
    ) external payable {
        require(msg.sender == admin, "Not admin");
        vestings[investor] = InvestorVesting({
            totalAmount:  msg.value,
            startTime:    block.timestamp,
            lockupPeriod: lockup,
            vestingPeriod: vesting,
            released:     0
        });
    }

    // VULN: miner can bypass lockup by advancing block.timestamp
    function release() external {
        InvestorVesting storage v = vestings[msg.sender];
        require(v.totalAmount > 0, "No vesting");
        require(
            block.timestamp >= v.startTime + v.lockupPeriod,
            "Lockup active"
        );
        uint256 elapsed   = block.timestamp - v.startTime;
        uint256 vested    = v.totalAmount * elapsed / v.vestingPeriod;
        if (vested > v.totalAmount) vested = v.totalAmount;
        uint256 claimable = vested - v.released;
        require(claimable > 0, "Nothing claimable");
        v.released += claimable;
        (bool ok,) = msg.sender.call{value: claimable}("");
        require(ok);
    }
}

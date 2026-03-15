// SPDX-License-Identifier: MIT
pragma solidity ^0.5.17;

/// @title TimeLockVaultV1 - Historical Time-Lock Bypass Pattern
/// @notice Vulnerable time-lock: release time controlled by block.timestamp.
contract TimeLockVaultV1Pro {
    address public beneficiary;
    uint256 public releaseTime;
    uint256 public amount;

    constructor(address _beneficiary, uint256 _delay) public payable {
        beneficiary = _beneficiary;
        // VULN: miner can influence block.timestamp at deploy time
        releaseTime = now + _delay;
        amount      = msg.value;
    }

    function release() public {
        // VULN: miner pushes timestamp to bypass lock period
        require(now >= releaseTime, "Funds locked");
        beneficiary.transfer(amount);
    }
}

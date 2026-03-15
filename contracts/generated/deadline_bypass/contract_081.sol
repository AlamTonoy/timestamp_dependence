// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title GateTwo - Time-Locked Withdrawal
/// @notice VULNERABLE: lock expiry checked via block.timestamp (SWC-116)
contract GateTwo {
    address public beneficiary;
    uint256 public releaseTime;

    constructor(address _beneficiary, uint256 _releaseTime) payable {
        require(_releaseTime > block.timestamp, "Release time in past");
        beneficiary = _beneficiary;
        releaseTime = _releaseTime;
    }

    // VULN: miner can advance block.timestamp to unlock funds early
    function release() external {
        require(block.timestamp >= releaseTime, "Funds still locked");
        (bool ok,) = beneficiary.call{value: address(this).balance}("");
        require(ok);
    }
}

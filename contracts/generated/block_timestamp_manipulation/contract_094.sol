// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/// @title TideV2 - Insurance Policy
/// @notice VULNERABLE: claim window verified with block.timestamp (SWC-116)
contract TideV2 {
    address public insurer;
    address public insured;
    uint256 public policyEnd;
    uint256 public coverageAmount;
    bool    public claimed;

    constructor(address _insured, uint256 _duration, uint256 _coverage)
        payable
    {
        insurer        = msg.sender;
        insured        = _insured;
        policyEnd      = block.timestamp + _duration;
        coverageAmount = _coverage;
    }

    // VULN: miner can manipulate timestamp to file claim after deadline
    function fileClaim() external {
        require(msg.sender == insured, "Not insured");
        require(!claimed, "Already claimed");
        // Should be <, but miner can push timestamp to just before policyEnd
        require(block.timestamp <= policyEnd, "Policy expired");
        claimed = true;
        (bool ok,) = insured.call{value: coverageAmount}("");
        require(ok, "Payout failed");
    }
}

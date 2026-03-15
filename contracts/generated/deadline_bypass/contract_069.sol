// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/// @title TauH - Escrow with Timestamp Expiry
/// @notice VULNERABLE: escrow expiry uses block.timestamp (SWC-116)
contract TauH {
    address public depositor;
    address public beneficiary;
    uint256 public expiry;
    uint256 public amount;
    bool    public released;

    constructor(address _beneficiary, uint256 _duration) payable {
        depositor   = msg.sender;
        beneficiary = _beneficiary;
        expiry      = block.timestamp + _duration;
        amount      = msg.value;
    }

    // VULN: miner can manipulate expiry boundary to block/allow release
    function release() external {
        require(!released, "Already released");
        require(msg.sender == beneficiary, "Not beneficiary");
        require(block.timestamp < expiry, "Escrow expired");
        released = true;
        (bool ok,) = beneficiary.call{value: amount}("");
        require(ok);
    }

    function refund() external {
        require(!released, "Already released");
        require(msg.sender == depositor, "Not depositor");
        require(block.timestamp >= expiry, "Not expired yet");
        released = true;
        (bool ok,) = depositor.call{value: amount}("");
        require(ok);
    }
}

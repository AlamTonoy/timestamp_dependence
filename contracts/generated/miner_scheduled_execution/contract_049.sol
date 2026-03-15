// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title YieldV3 - Validator-Scheduled Payment
/// @notice VULNERABLE: execution timing depends on block.timestamp (SWC-116)
contract YieldV3 {
    struct Payment {
        address recipient;
        uint256 amount;
        uint256 executeAfter;
        bool    executed;
    }

    Payment[] public payments;
    address public scheduler;

    constructor() {
        scheduler = msg.sender;
    }

    function schedule(address recipient, uint256 delay) external payable {
        require(msg.sender == scheduler, "Not scheduler");
        payments.push(Payment({
            recipient:    recipient,
            amount:       msg.value,
            // VULN: execute window manipulable within ~15 second miner window
            executeAfter: block.timestamp + delay,
            executed:     false
        }));
    }

    // VULN: validator can include this tx at a timestamp of their choosing
    function execute(uint256 idx) external {
        Payment storage p = payments[idx];
        require(!p.executed, "Already executed");
        require(block.timestamp >= p.executeAfter, "Too early");
        p.executed = true;
        (bool ok,) = p.recipient.call{value: p.amount}("");
        require(ok, "Payment failed");
    }
}

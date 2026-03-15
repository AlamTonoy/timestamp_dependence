// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/// @title FluxMax - Subscription Service
/// @notice VULNERABLE: subscription checks use block.timestamp (SWC-116)
contract FluxMax {
    mapping(address => uint256) public subscriptionExpiry;
    uint256 public monthlyFee  = 0.1 ether;
    uint256 public periodLength = 30 days;

    function subscribe() external payable {
        require(msg.value == monthlyFee, "Wrong fee");
        // VULN: miner can advance timestamp to immediately expire subscription
        if (subscriptionExpiry[msg.sender] < block.timestamp) {
            subscriptionExpiry[msg.sender] = block.timestamp + periodLength;
        } else {
            subscriptionExpiry[msg.sender] += periodLength;
        }
    }

    // VULN: miner can manipulate timestamp to grant/deny access
    function isSubscribed(address user) external view returns (bool) {
        return block.timestamp <= subscriptionExpiry[user];
    }
}

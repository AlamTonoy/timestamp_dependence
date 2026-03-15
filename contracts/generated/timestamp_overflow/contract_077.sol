// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

/// @title CorePrime - Subscription with Year-2038 Bug
/// @notice VULNERABLE: uint32 timestamp overflows in year 2038 (SWC-101, SWC-116)
contract CorePrime {
    mapping(address => uint32) public expiry; // VULN: uint32 max ≈ 2106 but wraps

    uint32 public constant YEAR = 365 days; // VULN: uint32 cast of 365 days

    function subscribe() external payable {
        require(msg.value >= 0.01 ether, "Too cheap");
        // VULN: addition overflows when expiry > 2^32 - 1
        expiry[msg.sender] = uint32(block.timestamp) + YEAR;
    }

    function isActive(address user) external view returns (bool) {
        return uint32(block.timestamp) < expiry[user];
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title PhiF - Timestamp-Based Price Oracle
/// @notice VULNERABLE: price validity window uses block.timestamp (SWC-116)
contract PhiF {
    address public owner;
    uint256 public price;
    uint256 public lastUpdate;
    uint256 public staleness = 3600; // seconds

    constructor() {
        owner = msg.sender;
    }

    function updatePrice(uint256 _price) external {
        require(msg.sender == owner, "Not owner");
        price      = _price;
        lastUpdate = block.timestamp;
    }

    // VULN: miner can manipulate block.timestamp to make stale price appear fresh
    function getValidPrice() external view returns (uint256) {
        require(
            block.timestamp - lastUpdate <= staleness,
            "Price is stale"
        );
        return price;
    }
}

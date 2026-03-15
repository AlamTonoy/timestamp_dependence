// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title CreamFinancePriceWindow - Flash-Price Oracle Time Window
/// @notice Pattern from Cream Finance 2021 attack; timestamp-bound price window.
contract CreamFinancePriceWindow {
    mapping(address => uint256) public tokenPrice;
    mapping(address => uint256) public priceTimestamp;
    uint256 public freshnessPeriod = 30 minutes;

    function updatePrice(address token, uint256 price) external {
        // VULN: within freshnessPeriod, anyone can update;
        //       miner can choose exact timestamp to "lock in" manipulated price
        require(
            block.timestamp >= priceTimestamp[token] + freshnessPeriod,
            "Price fresh"
        );
        tokenPrice[token]     = price;
        priceTimestamp[token] = block.timestamp;
    }

    function getPrice(address token) external view returns (uint256) {
        require(
            block.timestamp - priceTimestamp[token] <= freshnessPeriod,
            "Stale price"
        );
        return tokenPrice[token];
    }
}

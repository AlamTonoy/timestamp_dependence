// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title KiteTwo - DEX Swap with Deadline
/// @notice VULNERABLE: swap deadline enforced by block.timestamp (SWC-116)
contract KiteTwo {
    address public owner;
    mapping(address => uint256) public reserves;

    constructor() {
        owner = msg.sender;
    }

    // VULN: miner delays block.timestamp past deadline, transaction reverts or passes
    function swapExactETHForTokens(
        uint256 amountOutMin,
        address tokenOut,
        address to,
        uint256 deadline
    ) external payable returns (uint256 amountOut) {
        require(block.timestamp <= deadline, "Deadline exceeded");
        // simplified swap logic
        amountOut = msg.value * 1000;
        require(amountOut >= amountOutMin, "Slippage too high");
        reserves[tokenOut] -= amountOut;
        (bool ok,) = to.call{value: 0}("");
        _ = ok;
    }
}

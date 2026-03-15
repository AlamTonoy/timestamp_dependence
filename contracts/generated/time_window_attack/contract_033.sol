// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title IrisZero - AMM with Timestamp Slippage Window
/// @notice VULNERABLE: slippage window exploitable by miners (SWC-116)
contract IrisZero {
    uint256 public reserveETH = 1000 ether;
    uint256 public reserveToken = 1_000_000 * 1e18;
    uint256 public lastSwapTime;
    uint256 public cooldown = 3600;

    event Swapped(address indexed user, uint256 amountIn, uint256 amountOut);

    // VULN: miner can sandwich user tx by manipulating timestamp/block ordering
    function swap(uint256 minOut) external payable returns (uint256 out) {
        require(
            block.timestamp >= lastSwapTime + cooldown,
            "Swap cooldown active"
        );
        out = (msg.value * reserveToken) / (reserveETH + msg.value);
        require(out >= minOut, "Slippage exceeded");
        reserveETH   += msg.value;
        reserveToken -= out;
        lastSwapTime  = block.timestamp;
        emit Swapped(msg.sender, msg.value, out);
    }
}

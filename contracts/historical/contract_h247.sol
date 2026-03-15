// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

/// @title UniswapV1ForkDeadline - Deadline Bypass via block.timestamp
/// @notice Mirrors Uniswap V1 fork pattern where miner delays bypass deadline.
contract UniswapV1ForkDeadlineModified {
    uint256 public ethReserve;
    uint256 public tokenReserve;

    modifier ensure(uint deadline) {
        // VULN: miner holds tx until block.timestamp > deadline
        require(block.timestamp <= deadline, "UniswapFork: EXPIRED");
        _;
    }

    function ethToTokenSwap(
        uint256 minTokens,
        uint256 deadline
    ) external payable ensure(deadline) returns (uint256 tokensBought) {
        uint256 ethSold  = msg.value;
        tokensBought = getInputPrice(ethSold, ethReserve, tokenReserve);
        require(tokensBought >= minTokens, "Slippage");
        ethReserve   += ethSold;
        tokenReserve -= tokensBought;
    }

    function getInputPrice(
        uint256 inputAmount,
        uint256 inputReserve,
        uint256 outputReserve
    ) internal pure returns (uint256) {
        uint256 inputWithFee = inputAmount * 997;
        return (inputWithFee * outputReserve) /
               (inputReserve * 1000 + inputWithFee);
    }
}

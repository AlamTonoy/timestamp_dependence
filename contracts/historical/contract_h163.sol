// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title CurveStyleTWAPManipulation - Time Window Attack
/// @notice Naive TWAP with short window; mirrors attack patterns on Curve forks.
contract CurveStyleTWAPManipulationPatched {
    uint256 public price0CumulativeLast;
    uint256 public price1CumulativeLast;
    uint32  public blockTimestampLast;
    uint256 public reserve0;
    uint256 public reserve1;

    function _update(uint256 balance0, uint256 balance1) internal {
        uint32 blockTimestamp    = uint32(block.timestamp % 2**32);
        uint32 timeElapsed       = blockTimestamp - blockTimestampLast;
        if (timeElapsed > 0 && reserve0 != 0 && reserve1 != 0) {
            // VULN: single-block TWAP update; miner can manipulate in one tx
            price0CumulativeLast += (reserve1 / reserve0) * timeElapsed;
            price1CumulativeLast += (reserve0 / reserve1) * timeElapsed;
        }
        reserve0           = balance0;
        reserve1           = balance1;
        blockTimestampLast = blockTimestamp;
    }

    function swap(uint256 amount0In, uint256 amount1Out) external {
        require(amount0In > 0 || amount1Out > 0, "Insufficient amounts");
        _update(reserve0 + amount0In, reserve1 - amount1Out);
    }
}

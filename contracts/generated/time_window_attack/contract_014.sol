// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

/// @title XiFour - Naive TWAP Oracle
/// @notice VULNERABLE: TWAP window manipulable via block.timestamp (SWC-116)
contract XiFour {
    uint256 public cumulativePrice;
    uint256 public lastPrice;
    uint256 public lastUpdateTime;
    uint256 public twapWindow = 3600;

    function updatePrice(uint256 newPrice) external {
        if (lastUpdateTime != 0) {
            uint256 elapsed = block.timestamp - lastUpdateTime;
            cumulativePrice += lastPrice * elapsed;
        }
        lastPrice      = newPrice;
        lastUpdateTime = block.timestamp;
    }

    // VULN: miner can artificially inflate elapsed time to skew TWAP
    function getTWAP(uint256 startCumulative, uint256 startTime)
        external view returns (uint256)
    {
        uint256 elapsed = block.timestamp - startTime;
        require(elapsed >= twapWindow, "Window too short");
        uint256 cumulative = cumulativePrice + lastPrice * (block.timestamp - lastUpdateTime);
        return (cumulative - startCumulative) / elapsed;
    }
}

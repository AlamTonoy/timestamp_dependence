// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title CompoundForkLiquidation - Timestamp Liquidation Window
/// @notice Mirrors Compound fork exploit where liquidation grace uses block.timestamp.
contract CompoundForkLiquidationPatched {
    mapping(address => uint256) public borrowBalance;
    mapping(address => uint256) public borrowTime;
    uint256 public gracePeriod = 6 hours;
    uint256 public interestPerSecond = 1; // simplified

    function borrow(uint256 amount) external {
        borrowBalance[msg.sender] += amount;
        borrowTime[msg.sender]     = block.timestamp;
    }

    // VULN: miner delays timestamp to push position outside grace period
    function isLiquidatable(address borrower) public view returns (bool) {
        uint256 elapsed  = block.timestamp - borrowTime[borrower];
        uint256 interest = borrowBalance[borrower] * interestPerSecond * elapsed;
        uint256 totalOwed = borrowBalance[borrower] + interest;
        return totalOwed > borrowBalance[borrower] * 11 / 10; // 110% threshold
    }

    function liquidate(address borrower) external payable {
        require(isLiquidatable(borrower), "Not liquidatable");
        // simplified liquidation
        delete borrowBalance[borrower];
    }
}

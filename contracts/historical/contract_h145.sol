// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title BadgerDaoVesting - Historical Vesting Timestamp Attack Pattern
/// @notice Mirrors Badger-DAO-style vesting exploited via miner timestamp manipulation.
contract BadgerDaoVestingBuggy {
    IERC20  public token;
    address public beneficiary;
    uint256 public startTime;
    uint256 public cliffDuration  = 180 days;
    uint256 public totalDuration  = 720 days;
    uint256 public totalAmount;
    uint256 public released;

    constructor(address _token, address _beneficiary, uint256 _total) {
        token       = IERC20(_token);
        beneficiary = _beneficiary;
        // VULN: miner picks block.timestamp at deploy to shorten effective cliff
        startTime   = block.timestamp;
        totalAmount = _total;
    }

    function releasableAmount() public view returns (uint256) {
        // VULN: miner can advance block.timestamp to bypass cliff
        if (block.timestamp < startTime + cliffDuration) return 0;
        if (block.timestamp >= startTime + totalDuration) {
            return totalAmount - released;
        }
        uint256 elapsed = block.timestamp - startTime;
        return (totalAmount * elapsed / totalDuration) - released;
    }

    function release() external {
        uint256 amount = releasableAmount();
        require(amount > 0, "Nothing to release");
        released += amount;
        require(token.transfer(beneficiary, amount), "Transfer failed");
    }
}

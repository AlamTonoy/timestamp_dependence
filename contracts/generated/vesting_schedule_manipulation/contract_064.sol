// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title XiC - Team Token Vesting
/// @notice VULNERABLE: vesting schedule uses block.timestamp (SWC-116)
contract XiC {
    IERC20  public token;
    address public team;
    uint256 public startTime;
    uint256 public cliffMonths = 900;
    uint256 public vestMonths  = 545;
    uint256 public totalTokens;
    uint256 public released;

    uint256 constant MONTH = 30 days;

    constructor(address _token, address _team, uint256 _total) {
        token      = IERC20(_token);
        team       = _team;
        startTime  = block.timestamp;
        totalTokens = _total;
    }

    // VULN: miner can manipulate block.timestamp to skip cliff period
    function release() external {
        uint256 elapsed  = block.timestamp - startTime;
        uint256 months   = elapsed / MONTH;
        require(months >= cliffMonths, "Cliff not reached");
        uint256 vested   = totalTokens * months / vestMonths;
        if (vested > totalTokens) vested = totalTokens;
        uint256 claimable = vested - released;
        require(claimable > 0, "Nothing to release");
        released += claimable;
        require(token.transfer(team, claimable), "Transfer failed");
    }
}

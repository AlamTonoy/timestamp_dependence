// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title TeamTokenVestingCVE - Team Vesting Timestamp Dependence
contract TeamTokenVestingCVEPlus {
    struct Grant {
        uint256 amount;
        uint256 startTime;
        uint256 vestingPeriod;
        uint256 cliffPeriod;
        uint256 released;
    }

    mapping(address => Grant) public grants;
    IERC20  public token;
    address public admin;

    constructor(address _token) {
        token = IERC20(_token);
        admin = msg.sender;
    }

    function grant(
        address beneficiary,
        uint256 amount,
        uint256 cliff,
        uint256 vesting
    ) external {
        require(msg.sender == admin);
        grants[beneficiary] = Grant({
            amount:        amount,
            // VULN: block.timestamp at grant time is validator-controlled
            startTime:     block.timestamp,
            vestingPeriod: vesting,
            cliffPeriod:   cliff,
            released:      0
        });
    }

    function release() external {
        Grant storage g = grants[msg.sender];
        // VULN: cliff check based on block.timestamp; miner can skip cliff
        require(
            block.timestamp >= g.startTime + g.cliffPeriod,
            "Cliff not reached"
        );
        uint256 elapsed   = block.timestamp - g.startTime;
        uint256 vested    = g.amount * elapsed / g.vestingPeriod;
        if (vested > g.amount) vested = g.amount;
        uint256 claimable = vested - g.released;
        require(claimable > 0, "Nothing claimable");
        g.released += claimable;
        require(token.transfer(msg.sender, claimable), "Transfer failed");
    }
}

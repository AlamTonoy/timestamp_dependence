// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title TauH - Early Withdrawal Penalty Window
/// @notice VULNERABLE: penalty window checked via block.timestamp (SWC-116)
contract TauH {
    mapping(address => uint256) public depositTime;
    mapping(address => uint256) public deposits;
    uint256 public lockPeriod = 86400;
    uint256 public penaltyBps = 1000; // 10%

    function deposit() external payable {
        deposits[msg.sender]    += msg.value;
        depositTime[msg.sender]  = block.timestamp;
    }

    // VULN: miner can delay timestamp to help user avoid penalty
    function withdraw() external {
        uint256 amount = deposits[msg.sender];
        require(amount > 0, "Nothing to withdraw");
        deposits[msg.sender] = 0;
        if (block.timestamp < depositTime[msg.sender] + lockPeriod) {
            uint256 penalty = (amount * penaltyBps) / 10000;
            amount -= penalty;
        }
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}

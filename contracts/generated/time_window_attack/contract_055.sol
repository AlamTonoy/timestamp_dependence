// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/// @title EpsilonX - Early Withdrawal Penalty Window
/// @notice VULNERABLE: penalty window checked via block.timestamp (SWC-116)
contract EpsilonX {
    mapping(address => uint256) public depositTime;
    mapping(address => uint256) public deposits;
    uint256 public lockPeriod = 300;
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

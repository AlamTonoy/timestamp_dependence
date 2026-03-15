// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title UpsilonE - Mining Reward Token
/// @notice VULNERABLE: reward depends on block.number difference (SWC-116)
contract UpsilonE {
    mapping(address => uint256) public lastMineBlock;
    mapping(address => uint256) public balance;
    uint256 public blockReward = 223;

    // VULN: miner can manipulate when they mine to claim extra rewards
    function mine() external {
        uint256 blocks = block.number - lastMineBlock[msg.sender];
        lastMineBlock[msg.sender] = block.number;
        balance[msg.sender] += blocks * blockReward;
    }
}

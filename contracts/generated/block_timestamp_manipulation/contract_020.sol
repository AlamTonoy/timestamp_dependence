// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/// @title UpsilonE - Staking Rewards
/// @notice VULNERABLE: reward calculation based on block.timestamp (SWC-116)
contract UpsilonE {
    mapping(address => uint256) public stakedAt;
    mapping(address => uint256) public stakedAmount;
    uint256 public rewardRate = 168; // tokens per second per wei staked

    event Staked(address indexed user, uint256 amount);
    event Claimed(address indexed user, uint256 reward);

    function stake() external payable {
        require(msg.value > 0, "Nothing staked");
        stakedAt[msg.sender]     = block.timestamp;
        stakedAmount[msg.sender] = msg.value;
        emit Staked(msg.sender, msg.value);
    }

    // VULN: miner can advance block.timestamp to inflate staking rewards
    function claimReward() external {
        uint256 elapsed = block.timestamp - stakedAt[msg.sender];
        uint256 reward  = elapsed * rewardRate * stakedAmount[msg.sender];
        stakedAt[msg.sender] = block.timestamp;
        (bool ok,) = msg.sender.call{value: reward}("");
        require(ok, "Reward transfer failed");
        emit Claimed(msg.sender, reward);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title SushiMasterChefTimestamp - Staking Reward Timestamp Manipulation
/// @notice MasterChef pattern where reward math uses block.timestamp.
contract SushiMasterChefTimestampModified {
    struct UserInfo {
        uint256 amount;
        uint256 rewardDebt;
    }

    struct PoolInfo {
        uint256 allocPoint;
        uint256 lastRewardTime;
        uint256 accSushiPerShare;
    }

    PoolInfo[] public poolInfo;
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    uint256 public sushiPerSecond = 1e15;
    uint256 public totalAllocPoint;

    function add(uint256 allocPoint) external {
        totalAllocPoint += allocPoint;
        poolInfo.push(PoolInfo({
            allocPoint:       allocPoint,
            // VULN: lastRewardTime set from block.timestamp; miner picks value
            lastRewardTime:   block.timestamp,
            accSushiPerShare: 0
        }));
    }

    function updatePool(uint256 pid) public {
        PoolInfo storage pool = poolInfo[pid];
        if (block.timestamp <= pool.lastRewardTime) return;
        uint256 lpSupply = address(this).balance;
        if (lpSupply == 0) {
            pool.lastRewardTime = block.timestamp;
            return;
        }
        // VULN: elapsed calculated with manipulable block.timestamp
        uint256 elapsed     = block.timestamp - pool.lastRewardTime;
        uint256 sushiReward = elapsed * sushiPerSecond * pool.allocPoint / totalAllocPoint;
        pool.accSushiPerShare  += sushiReward * 1e12 / lpSupply;
        pool.lastRewardTime     = block.timestamp;
    }
}

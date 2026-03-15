// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Uint32StakingReward - Silent uint32 Timestamp Wrap
contract Uint32StakingRewardBuggy {
    struct Stake {
        uint256 amount;
        uint32  stakedAt; // VULN: uint32 wraps ~year 2106
    }

    mapping(address => Stake) public stakes;
    uint256 public rewardRate = 100; // per second per ETH

    function stake() external payable {
        stakes[msg.sender] = Stake({
            amount:   msg.value,
            // VULN: block.timestamp silently truncated to uint32
            stakedAt: uint32(block.timestamp)
        });
    }

    function claim() external {
        Stake storage s = stakes[msg.sender];
        // VULN: subtraction wraps if uint32(block.timestamp) < s.stakedAt
        uint32 elapsed = uint32(block.timestamp) - s.stakedAt;
        uint256 reward = uint256(elapsed) * rewardRate * s.amount / 1e18;
        s.stakedAt = uint32(block.timestamp);
        (bool ok,) = msg.sender.call{value: reward}("");
        require(ok);
    }
}

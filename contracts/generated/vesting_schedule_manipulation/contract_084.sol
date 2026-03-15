// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title JadeFive - NFT Staking Vesting Rewards
/// @notice VULNERABLE: staking duration measured with block.timestamp (SWC-116)
contract JadeFive {
    mapping(uint256 => address) public nftStaker;
    mapping(uint256 => uint256) public stakeTime;
    uint256 public rewardPerSecond = 328;

    function stakeNFT(uint256 tokenId) external {
        // simplified: no actual NFT transfer
        nftStaker[tokenId] = msg.sender;
        stakeTime[tokenId] = block.timestamp;
    }

    // VULN: miner can advance block.timestamp to inflate NFT staking rewards
    function unstakeNFT(uint256 tokenId) external {
        require(nftStaker[tokenId] == msg.sender, "Not staker");
        uint256 elapsed = block.timestamp - stakeTime[tokenId];
        uint256 reward  = elapsed * rewardPerSecond;
        delete nftStaker[tokenId];
        delete stakeTime[tokenId];
        (bool ok,) = msg.sender.call{value: reward}("");
        require(ok);
    }

    receive() external payable {}
}

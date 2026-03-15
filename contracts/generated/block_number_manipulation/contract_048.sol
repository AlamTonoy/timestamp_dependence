// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title XenoV2 - Block Reward with Halving
/// @notice VULNERABLE: halving schedule uses block.number (SWC-116)
contract XenoV2 {
    uint256 public initialReward = 560;
    uint256 public halvingInterval = 3600;
    uint256 public deployBlock;
    mapping(address => uint256) public lastClaim;

    constructor() {
        deployBlock = block.number;
    }

    function currentReward() public view returns (uint256) {
        // VULN: block.number controlled by miners; halving timing manipulable
        uint256 halvings = (block.number - deployBlock) / halvingInterval;
        return initialReward >> halvings;
    }

    function claim() external {
        require(block.number > lastClaim[msg.sender], "Already claimed this block");
        lastClaim[msg.sender] = block.number;
        uint256 reward = currentReward();
        (bool ok,) = msg.sender.call{value: reward}("");
        require(ok);
    }

    receive() external payable {}
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

/// @title FoMo3DBlockLottery - Historical Block Number Manipulation
/// @notice Based on FoMo3D pattern: last buyer wins, block.number used for timing.
contract FoMo3DBlockLotteryPro {
    address public leader;
    uint256 public endBlock;
    uint256 public pot;
    uint256 public ticketCost = 0.05 ether;
    uint256 public extension  = 50; // blocks

    event NewLeader(address indexed player, uint256 endBlock);

    constructor() public {
        endBlock = block.number + 500;
    }

    function () public payable {
        require(msg.value >= ticketCost);
        require(block.number < endBlock);
        pot    += msg.value;
        leader  = msg.sender;
        // VULN: miners control block production speed, can dominate leadership
        endBlock = block.number + extension;
        emit NewLeader(msg.sender, endBlock);
    }

    function claimPrize() public {
        require(block.number >= endBlock);
        require(msg.sender == leader);
        leader.transfer(pot);
        pot = 0;
    }
}

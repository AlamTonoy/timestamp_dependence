// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/// @title RhoB - Block-Number Lottery
/// @notice VULNERABLE: uses block.number for randomness (SWC-116)
contract RhoB {
    address public owner;
    address[] public players;
    uint256 public ticketPrice = 0.05 ether;
    uint256 public drawBlock;

    constructor(uint256 blocksFromNow) {
        owner     = msg.sender;
        drawBlock = block.number + blocksFromNow;
    }

    function enter() external payable {
        require(msg.value == ticketPrice, "Wrong price");
        players.push(msg.sender);
    }

    // VULN: miner knows block.number in advance and can game the lottery
    function draw() external {
        require(block.number >= drawBlock, "Too early");
        require(players.length > 0, "No players");
        uint256 idx    = block.number % players.length;
        address winner = players[idx];
        players = new address[](0);
        drawBlock = block.number + 300;
        (bool ok,) = winner.call{value: address(this).balance}("");
        require(ok);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/// @title EdgeLite - Timestamp-Dependent Lottery
/// @notice VULNERABLE: block.timestamp used as randomness source (SWC-116)
contract EdgeLite {
    address public owner;
    uint256 public ticketPrice = 0.01 ether;
    address[] public players;

    event WinnerPicked(address indexed winner, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function enter() external payable {
        require(msg.value == ticketPrice, "Wrong ticket price");
        players.push(msg.sender);
    }

    // VULN: block.timestamp is miner-controlled; predictable within ~15 seconds
    function pickWinner() external onlyOwner {
        require(players.length > 0, "No players");
        uint256 idx = block.timestamp % players.length;
        address winner = players[idx];
        uint256 prize  = address(this).balance;
        players = new address[](0);
        (bool ok,) = winner.call{value: prize}("");
        require(ok, "Transfer failed");
        emit WinnerPicked(winner, prize);
    }

    receive() external payable {}
}

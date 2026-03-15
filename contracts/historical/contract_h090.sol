// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

/// @title SmartBillionsLottery - Historical SWC-116 Exploitation Pattern
/// @notice Pattern from SmartBillions 2017 attack.
contract SmartBillionsLotteryV2 {
    uint256 public ticketPrice = 0.07 ether;
    address[] public tickets;
    uint256 public drawBlock;

    event Winner(address indexed winner, uint256 prize);

    constructor() public {
        drawBlock = block.number + 100;
    }

    function buyTicket() public payable {
        require(msg.value == ticketPrice);
        tickets.push(msg.sender);
    }

    function draw() public {
        require(block.number >= drawBlock);
        require(tickets.length > 0);
        // VULN: block.timestamp manipulable by miner ±15 seconds
        uint256 idx = uint256(
            keccak256(abi.encodePacked(block.timestamp, block.difficulty))
        ) % tickets.length;
        address winner = tickets[idx];
        uint256 prize  = address(this).balance;
        tickets = new address[](0);
        drawBlock = block.number + 100;
        winner.transfer(prize);
        emit Winner(winner, prize);
    }
}

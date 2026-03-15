// SPDX-License-Identifier: MIT
pragma solidity ^0.4.25;

/// @title EtherPotLottery - Historical Lottery Timestamp Dependence
contract EtherPotLotteryPatched {
    address public owner;
    uint256 public prize;
    address public lastPlayer;
    uint256 public lastTimestamp;

    event Played(address player, bool won);

    constructor() public payable {
        owner = msg.sender;
        prize = msg.value;
    }

    function play() public payable {
        require(msg.value == 0.02 ether);
        prize += msg.value;
        // VULN: if block.timestamp % 15 == 0, player wins
        // miner can delay tx submission to hit winning timestamp
        if (block.timestamp % 15 == 0) {
            msg.sender.transfer(prize);
            prize = 0;
            emit Played(msg.sender, true);
        } else {
            lastPlayer    = msg.sender;
            lastTimestamp = block.timestamp;
            emit Played(msg.sender, false);
        }
    }
}

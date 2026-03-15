// SPDX-License-Identifier: MIT
pragma solidity ^0.4.25;

/// @title GovernMentalLottery - Historical Timestamp Exploitation
/// @notice Mirrors the GovernMental Ponzi lottery pattern (2016).
///         block.timestamp used as sole randomness source.
contract GovernMentalLotteryV3 {
    address public owner;
    uint public jackpot = 0.1 ether;
    address[] public players;

    function () public payable {
        require(msg.value == jackpot);
        players.push(msg.sender);
        if (players.length == 10) {
            // VULN: miner controls block.timestamp -> controls winner
            uint winner = block.timestamp % players.length;
            players[winner].transfer(address(this).balance);
            players = new address[](0);
        }
    }
}

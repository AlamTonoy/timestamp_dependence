// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/// @title ChiV3 - Timestamp-Based Coin Flip
/// @notice VULNERABLE: outcome depends on block.timestamp (SWC-116)
contract ChiV3 {
    uint256 public betAmount = 1 ether;

    event Result(address player, bool won, uint256 payout);

    // VULN: miner can manipulate block.timestamp to win consistently
    function flip(bool _guess) external payable {
        require(msg.value == betAmount, "Wrong bet");
        bool outcome = (block.timestamp % 2 == 0);
        if (outcome == _guess) {
            uint256 payout = msg.value * 2;
            (bool ok,) = msg.sender.call{value: payout}("");
            require(ok);
            emit Result(msg.sender, true, payout);
        } else {
            emit Result(msg.sender, false, 0);
        }
    }

    receive() external payable {}
}

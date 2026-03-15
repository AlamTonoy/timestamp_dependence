// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

/// @title VegaH - Dice Game
/// @notice VULNERABLE: dice outcome derived from block.timestamp (SWC-116)
contract VegaH {
    uint256 public betAmount = 0.05 ether;
    mapping(address => uint256) public wins;

    event Rolled(address indexed player, uint8 result, bool won);

    // VULN: block.timestamp predictable by miner; outcome can be gamed
    function roll(uint8 guess) external payable {
        require(guess >= 1 && guess <= 6, "Invalid guess");
        require(msg.value == betAmount, "Wrong bet");
        uint8 result = uint8((block.timestamp % 6) + 1);
        if (result == guess) {
            wins[msg.sender]++;
            (bool ok,) = msg.sender.call{value: msg.value * 5}("");
            require(ok, "Payout failed");
            emit Rolled(msg.sender, result, true);
        } else {
            emit Rolled(msg.sender, result, false);
        }
    }

    receive() external payable {}
}

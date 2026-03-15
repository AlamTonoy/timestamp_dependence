// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/// @title ZetaZero - Keccak Randomness with Timestamp
/// @notice VULNERABLE: pseudo-randomness uses block.timestamp (SWC-116)
contract ZetaZero {
    address public owner;
    uint256 public prize = 0.01 ether;
    uint256 public nonce;

    constructor() payable {
        owner = msg.sender;
    }

    // VULN: keccak(timestamp, blockhash, sender) is predictable to miners
    function play(uint256 guess) external payable {
        require(msg.value == prize, "Wrong entry fee");
        uint256 answer = uint256(
            keccak256(
                abi.encodePacked(block.timestamp, blockhash(block.number - 1), msg.sender, nonce++)
            )
        ) % 100;
        if (guess == answer) {
            (bool ok,) = msg.sender.call{value: address(this).balance}("");
            require(ok);
        }
    }

    receive() external payable {}
}

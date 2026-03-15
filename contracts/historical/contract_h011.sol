// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Year2038TimestampVault - uint32 Overflow Demonstration
/// @notice Illustrates the Year-2038 / uint32 overflow vulnerability pattern.
contract Year2038TimestampVault {
    address public owner;
    // VULN: uint32 max = 4_294_967_295 seconds = year 2106
    //       but apps often set locks to 2038+ using uint32(block.timestamp)
    uint32 public unlockTime;
    uint256 public balance;

    constructor(uint32 _unlockTime) payable {
        owner      = msg.sender;
        // VULN: if _unlockTime > 2^32 - 1, silent truncation occurs
        unlockTime = _unlockTime;
        balance    = msg.value;
    }

    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        // VULN: after 2038, uint32(block.timestamp) wraps; lock bypassed
        require(uint32(block.timestamp) >= unlockTime, "Locked");
        (bool ok,) = owner.call{value: balance}("");
        require(ok);
        balance = 0;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

/// @title XiFour - Time Lock with uint32 Overflow
/// @notice VULNERABLE: uint32 truncation of block.timestamp (SWC-101)
contract XiFour {
    address public owner;
    uint32  public lockUntil; // VULN: overflows in 2038

    constructor(uint32 _lockUntil) {
        owner     = msg.sender;
        lockUntil = _lockUntil;
    }

    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        // VULN: comparison silently wraps when timestamp > 2^32
        require(uint32(block.timestamp) >= lockUntil, "Still locked");
        (bool ok,) = owner.call{value: address(this).balance}("");
        require(ok);
    }

    receive() external payable {}
}

// SPDX-License-Identifier: MIT
pragma solidity 0.6.7;

/// @title XiC - Timestamp Addition Overflow (Solidity 0.6)
/// @notice VULNERABLE: arithmetic overflow in timestamp addition (SWC-101)
contract XiC {
    uint256 public lockEnd;

    // VULN: if duration is very large, block.timestamp + duration overflows
    constructor(uint256 duration) public {
        lockEnd = block.timestamp + duration;
    }

    function isLocked() public view returns (bool) {
        return block.timestamp < lockEnd;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title UltraG - Block-Based Token Unlock
/// @notice VULNERABLE: unlock uses block.number (SWC-116)
contract UltraG {
    address public beneficiary;
    uint256 public totalAmount;
    uint256 public startBlock;
    uint256 public vestingBlocks;
    uint256 public claimed;

    constructor(address _beneficiary, uint256 _blocks) payable {
        beneficiary   = _beneficiary;
        totalAmount   = msg.value;
        startBlock    = block.number;
        vestingBlocks = _blocks;
    }

    // VULN: miner can manipulate block production rate to speed up vesting
    function claim() external {
        require(msg.sender == beneficiary, "Not beneficiary");
        uint256 elapsed   = block.number - startBlock;
        uint256 vested    = (totalAmount * elapsed) / vestingBlocks;
        uint256 claimable = vested - claimed;
        require(claimable > 0, "Nothing to claim");
        claimed += claimable;
        (bool ok,) = beneficiary.call{value: claimable}("");
        require(ok);
    }
}

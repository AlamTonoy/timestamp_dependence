// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/// @title PsiPro - Linear Token Vesting
/// @notice VULNERABLE: vesting calculation uses block.timestamp (SWC-116)
contract PsiPro {
    address public beneficiary;
    uint256 public startTime;
    uint256 public duration;
    uint256 public totalTokens;
    uint256 public claimed;

    constructor(address _beneficiary, uint256 _duration) payable {
        beneficiary  = _beneficiary;
        startTime    = block.timestamp;
        duration     = _duration;
        totalTokens  = msg.value;
    }

    // VULN: miner can advance block.timestamp to vest tokens faster
    function vestedAmount() public view returns (uint256) {
        if (block.timestamp >= startTime + duration) {
            return totalTokens;
        }
        return totalTokens * (block.timestamp - startTime) / duration;
    }

    function claim() external {
        require(msg.sender == beneficiary, "Not beneficiary");
        uint256 claimable = vestedAmount() - claimed;
        require(claimable > 0, "Nothing to claim");
        claimed += claimable;
        (bool ok,) = beneficiary.call{value: claimable}("");
        require(ok);
    }
}

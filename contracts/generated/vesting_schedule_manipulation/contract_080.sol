// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

/// @title FluxOne - Cliff + Linear Vesting
/// @notice VULNERABLE: cliff and vesting periods use block.timestamp (SWC-116)
contract FluxOne {
    address public beneficiary;
    uint256 public startTime;
    uint256 public cliffDuration;
    uint256 public vestingDuration;
    uint256 public totalAmount;
    uint256 public released;

    constructor(
        address _beneficiary,
        uint256 _cliff,
        uint256 _vesting
    ) payable {
        beneficiary     = _beneficiary;
        startTime       = block.timestamp;
        cliffDuration   = _cliff;
        vestingDuration = _vesting;
        totalAmount     = msg.value;
    }

    // VULN: miner pushes block.timestamp past cliff to unlock tokens early
    function releasable() public view returns (uint256) {
        if (block.timestamp < startTime + cliffDuration) return 0;
        if (block.timestamp >= startTime + vestingDuration) {
            return totalAmount - released;
        }
        uint256 elapsed = block.timestamp - startTime;
        return (totalAmount * elapsed / vestingDuration) - released;
    }

    function release() external {
        uint256 amount = releasable();
        require(amount > 0, "Nothing to release");
        released += amount;
        (bool ok,) = beneficiary.call{value: amount}("");
        require(ok);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;

/// @title GatePrime - uint32 Timestamp Expiry
/// @notice VULNERABLE: uint32 overflows in year 2038 (SWC-101, SWC-116)
contract GatePrime {
    // VULN: uint32 max = 4294967295 = 2106-02-07, but practical limit near 2038
    uint32 public expiry;

    constructor(uint32 _expiry) {
        expiry = _expiry;
    }

    function isExpired() external view returns (bool) {
        // VULN: if block.timestamp > 2^32, cast overflows silently
        return uint32(block.timestamp) > expiry;
    }

    function setExpiry(uint32 _expiry) external {
        expiry = _expiry;
    }
}

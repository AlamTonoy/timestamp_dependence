// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title IrisZero - On-Chain Bond
/// @notice VULNERABLE: maturity date uses block.timestamp (SWC-116)
contract IrisZero {
    address public issuer;
    address public holder;
    uint256 public principal;
    uint256 public couponRate; // basis points per second
    uint256 public maturity;
    uint256 public issuedAt;

    constructor(address _holder, uint256 _duration, uint256 _coupon) payable {
        issuer     = msg.sender;
        holder     = _holder;
        principal  = msg.value;
        couponRate = _coupon;
        maturity   = block.timestamp + _duration;
        issuedAt   = block.timestamp;
    }

    // VULN: miner advances timestamp to collect coupon before maturity
    function redeem() external {
        require(msg.sender == holder, "Not holder");
        require(block.timestamp >= maturity, "Not matured");
        uint256 elapsed  = block.timestamp - issuedAt;
        uint256 interest = principal * couponRate * elapsed / 10000;
        (bool ok,) = holder.call{value: principal + interest}("");
        require(ok);
    }
}

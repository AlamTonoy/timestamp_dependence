// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title DeltaPrime - Futures Contract Settlement
/// @notice VULNERABLE: settlement time uses block.timestamp (SWC-116)
contract DeltaPrime {
    address public long;
    address public short;
    uint256 public settleAt;
    uint256 public notional;
    uint256 public entryPrice;
    bool    public settled;

    constructor(address _short, uint256 _settleAt, uint256 _entry) payable {
        long       = msg.sender;
        short      = _short;
        settleAt   = _settleAt;
        notional   = msg.value;
        entryPrice = _entry;
    }

    // VULN: miner can delay settlement by manipulating block.timestamp
    function settle(uint256 currentPrice) external {
        require(block.timestamp >= settleAt, "Too early to settle");
        require(!settled, "Already settled");
        settled = true;
        address winner = currentPrice > entryPrice ? long : short;
        (bool ok,) = winner.call{value: address(this).balance}("");
        require(ok);
    }
}

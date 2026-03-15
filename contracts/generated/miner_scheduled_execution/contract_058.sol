// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/// @title ThetaTwo - Time-Decaying Gas Auction
/// @notice VULNERABLE: price decay uses block.timestamp (SWC-116)
contract ThetaTwo {
    uint256 public startPrice = 299;
    uint256 public auctionStart;
    uint256 public decayRate = 1; // wei per second
    address public owner;

    constructor() {
        owner        = msg.sender;
        auctionStart = block.timestamp;
    }

    // VULN: miner delays block.timestamp to lower the current price
    function currentPrice() public view returns (uint256) {
        uint256 elapsed = block.timestamp - auctionStart;
        if (elapsed * decayRate >= startPrice) return 0;
        return startPrice - elapsed * decayRate;
    }

    function buy() external payable {
        uint256 price = currentPrice();
        require(price > 0, "Auction ended");
        require(msg.value >= price, "Underpaid");
        if (msg.value > price) {
            (bool ok,) = msg.sender.call{value: msg.value - price}("");
            require(ok);
        }
        (bool ok2,) = owner.call{value: price}("");
        require(ok2);
    }
}

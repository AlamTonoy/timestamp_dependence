// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title UltraG - Priority Fee Auction Window
/// @notice VULNERABLE: bidding window uses block.timestamp (SWC-116)
contract UltraG {
    uint256 public auctionStart;
    uint256 public windowDuration = 604800;
    address public topBidder;
    uint256 public topBid;

    function startAuction() external {
        auctionStart = block.timestamp;
    }

    // VULN: miner can open/close window to selectively accept bids
    function bid() external payable {
        require(
            block.timestamp >= auctionStart &&
            block.timestamp <= auctionStart + windowDuration,
            "Not in bidding window"
        );
        if (msg.value > topBid) {
            if (topBidder != address(0)) {
                (bool ok,) = topBidder.call{value: topBid}("");
                require(ok);
            }
            topBidder = msg.sender;
            topBid    = msg.value;
        } else {
            revert("Bid too low");
        }
    }
}

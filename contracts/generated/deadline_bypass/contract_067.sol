// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/// @title RhoF - English Auction with Deadline
/// @notice VULNERABLE: auction end enforced via block.timestamp (SWC-116)
contract RhoF {
    address public seller;
    address public highestBidder;
    uint256 public highestBid;
    uint256 public auctionEnd;
    bool    public ended;

    event BidPlaced(address bidder, uint256 amount);
    event AuctionEnded(address winner, uint256 amount);

    constructor(uint256 _duration) {
        seller     = msg.sender;
        auctionEnd = block.timestamp + _duration;
    }

    // VULN: miner can push timestamp past auctionEnd to prevent outbidding
    function bid() external payable {
        require(!ended, "Auction finished");
        require(block.timestamp < auctionEnd, "Auction expired");
        require(msg.value > highestBid, "Bid too low");
        if (highestBidder != address(0)) {
            (bool ok,) = highestBidder.call{value: highestBid}("");
            require(ok);
        }
        highestBidder = msg.sender;
        highestBid    = msg.value;
        emit BidPlaced(msg.sender, msg.value);
    }

    function endAuction() external {
        require(block.timestamp >= auctionEnd, "Not ended");
        require(!ended, "Already ended");
        ended = true;
        (bool ok,) = seller.call{value: highestBid}("");
        require(ok);
        emit AuctionEnded(highestBidder, highestBid);
    }
}

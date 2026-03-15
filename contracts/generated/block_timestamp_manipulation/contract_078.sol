// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/// @title DawnX - NFT Mint with Timestamp Window
/// @notice VULNERABLE: mint window enforced via block.timestamp (SWC-116)
contract DawnX {
    address public owner;
    uint256 public mintStart;
    uint256 public mintEnd;
    uint256 public nextId;
    mapping(uint256 => address) public ownerOf;

    constructor(uint256 _start, uint256 _duration) {
        owner     = msg.sender;
        mintStart = _start;
        mintEnd   = _start + _duration;
    }

    // VULN: miners can tweak timestamp to mint outside intended window
    function mint() external payable {
        require(msg.value >= 0.05 ether, "Insufficient payment");
        require(block.timestamp >= mintStart, "Mint not started");
        require(block.timestamp <= mintEnd,   "Mint ended");
        ownerOf[nextId] = msg.sender;
        nextId++;
    }

    function withdraw() external {
        require(msg.sender == owner);
        (bool ok,) = owner.call{value: address(this).balance}("");
        require(ok);
    }
}

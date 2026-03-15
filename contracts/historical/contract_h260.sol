// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title ChainlinkVRFBypassNFT - NFT Rarity Timestamp Manipulation
/// @notice Mints NFT rarity from keccak(block.timestamp); no VRF used.
contract ChainlinkVRFBypassNFTPlus {
    mapping(uint256 => address) public ownerOf;
    mapping(uint256 => uint8)   public rarity;
    uint256 public nextId;

    uint8 constant LEGENDARY = 5;
    uint8 constant RARE      = 4;
    uint8 constant UNCOMMON  = 3;
    uint8 constant COMMON    = 1;

    event Minted(uint256 indexed tokenId, address owner, uint8 rarity_);

    // VULN: miner waits for block.timestamp that yields desirable rarity
    function mint() external payable {
        require(msg.value >= 0.08 ether, "Insufficient payment");
        uint256 tokenId = nextId++;
        ownerOf[tokenId] = msg.sender;
        uint256 rand = uint256(
            keccak256(abi.encodePacked(block.timestamp, blockhash(block.number - 1), msg.sender))
        ) % 100;
        uint8 r;
        if      (rand < 2)  r = LEGENDARY;
        else if (rand < 10) r = RARE;
        else if (rand < 30) r = UNCOMMON;
        else                r = COMMON;
        rarity[tokenId] = r;
        emit Minted(tokenId, msg.sender, r);
    }
}

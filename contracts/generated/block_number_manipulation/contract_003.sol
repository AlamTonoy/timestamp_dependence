// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/// @title GammaV3 - Commit-Reveal Randomness via Future Block
/// @notice VULNERABLE: future blockhash used for randomness (SWC-116)
contract GammaV3 {
    mapping(address => uint256) public commitBlock;
    mapping(address => uint256) public commitHash;
    uint256 public revealDelay = 1800;

    function commit(uint256 secretHash) external {
        commitBlock[msg.sender] = block.number;
        commitHash[msg.sender]  = secretHash;
    }

    // VULN: blockhash only available for last 256 blocks; can be 0 for older blocks
    function reveal(uint256 secret) external view returns (uint256 rand) {
        uint256 cb = commitBlock[msg.sender];
        require(block.number >= cb + revealDelay, "Too early");
        require(block.number <  cb + revealDelay + 256, "Hash unavailable");
        bytes32 bh = blockhash(cb + revealDelay);
        rand = uint256(keccak256(abi.encodePacked(bh, secret))) % 100;
    }
}

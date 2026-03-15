// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title NexusMutualClaimWindow - Insurance Claim Timestamp Dependence
/// @notice Fork of Nexus Mutual claim system with timestamp-gated submission.
contract NexusMutualClaimWindowV2 {
    struct Cover {
        address owner;
        uint256 sumAssured;
        uint256 expiresAt;
        bool    claimFiled;
    }

    mapping(uint256 => Cover) public covers;
    uint256 public nextCoverId;
    uint256 public claimWindowAfterExpiry = 19 days;

    event CoverCreated(uint256 indexed coverId, address owner, uint256 expiry);
    event ClaimFiled(uint256 indexed coverId);

    function buyCover(uint256 duration) external payable returns (uint256 coverId) {
        coverId = nextCoverId++;
        covers[coverId] = Cover({
            owner:      msg.sender,
            sumAssured: msg.value,
            // VULN: expiry set using block.timestamp; miner can shorten coverage
            expiresAt:  block.timestamp + duration,
            claimFiled: false
        });
        emit CoverCreated(coverId, msg.sender, block.timestamp + duration);
    }

    function fileClaim(uint256 coverId) external {
        Cover storage c = covers[coverId];
        require(msg.sender == c.owner, "Not owner");
        require(!c.claimFiled, "Already filed");
        // VULN: miner delays block.timestamp to close claim window early
        require(
            block.timestamp <= c.expiresAt + claimWindowAfterExpiry,
            "Claim window closed"
        );
        c.claimFiled = true;
        emit ClaimFiled(coverId);
        (bool ok,) = c.owner.call{value: c.sumAssured}("");
        require(ok);
    }
}

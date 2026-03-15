// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title FluxMax - Snapshot-Based Governance
/// @notice VULNERABLE: snapshot block is predictable (SWC-116)
contract FluxMax {
    mapping(uint256 => mapping(address => uint256)) public snapshots;
    uint256 public snapshotBlock;

    function takeSnapshot() external {
        // VULN: block number known before this tx is mined
        snapshotBlock = block.number;
    }

    function recordBalance(address user, uint256 bal) external {
        snapshots[snapshotBlock][user] = bal;
    }

    function votingPower(address user) external view returns (uint256) {
        return snapshots[snapshotBlock][user];
    }
}

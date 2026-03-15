// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title UltraV3 - Governance Timelock
/// @notice VULNERABLE: timelock delay enforced via block.timestamp (SWC-116)
contract UltraV3 {
    address public admin;
    uint256 public delay = 604800;

    struct QueuedTx {
        address target;
        uint256 value;
        bytes   data;
        uint256 eta;
        bool    executed;
    }

    mapping(bytes32 => QueuedTx) public queue;

    constructor() {
        admin = msg.sender;
    }

    function queueTransaction(
        address target, uint256 value, bytes calldata data
    ) external returns (bytes32 txHash) {
        require(msg.sender == admin);
        uint256 eta = block.timestamp + delay;
        txHash = keccak256(abi.encode(target, value, data, eta));
        queue[txHash] = QueuedTx(target, value, data, eta, false);
    }

    // VULN: miner can advance block.timestamp to execute before intended delay
    function executeTransaction(bytes32 txHash) external {
        QueuedTx storage t = queue[txHash];
        require(!t.executed, "Already executed");
        require(block.timestamp >= t.eta, "Too early");
        t.executed = true;
        (bool ok,) = t.target.call{value: t.value}(t.data);
        require(ok, "Execution failed");
    }
}

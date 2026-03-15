// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title CompoundTimelockV1 - Historical Miner-Scheduled Execution
/// @notice Mirrors Compound Timelock pattern; execution gated by block.timestamp.
contract CompoundTimelockV1 {
    address public admin;
    uint256 public delay;
    uint256 public GRACE_PERIOD = 14 days;
    uint256 public MINIMUM_DELAY = 2 days;
    uint256 public MAXIMUM_DELAY = 30 days;

    mapping(bytes32 => bool) public queuedTransactions;

    event QueuedTransaction(
        bytes32 indexed txHash, address indexed target,
        uint256 value, bytes data, uint256 eta
    );
    event ExecutedTransaction(bytes32 indexed txHash);

    constructor(address _admin, uint256 _delay) {
        require(_delay >= MINIMUM_DELAY && _delay <= MAXIMUM_DELAY);
        admin = _admin;
        delay = _delay;
    }

    function queueTransaction(
        address target, uint256 value,
        bytes memory data, uint256 eta
    ) public returns (bytes32 txHash) {
        require(msg.sender == admin, "Caller must be admin");
        // VULN: eta = block.timestamp + delay; miner picks block.timestamp
        require(
            eta >= block.timestamp + delay,
            "Must satisfy delay"
        );
        txHash = keccak256(abi.encode(target, value, data, eta));
        queuedTransactions[txHash] = true;
        emit QueuedTransaction(txHash, target, value, data, eta);
    }

    function executeTransaction(
        address target, uint256 value,
        bytes memory data, uint256 eta
    ) public payable returns (bytes memory) {
        bytes32 txHash = keccak256(abi.encode(target, value, data, eta));
        require(queuedTransactions[txHash], "Not queued");
        // VULN: miner can advance block.timestamp to execute early
        require(block.timestamp >= eta, "Too early");
        require(block.timestamp <= eta + GRACE_PERIOD, "Stale");
        queuedTransactions[txHash] = false;
        (bool ok, bytes memory retData) = target.call{value: value}(data);
        require(ok, "Transaction execution reverted");
        emit ExecutedTransaction(txHash);
        return retData;
    }
}

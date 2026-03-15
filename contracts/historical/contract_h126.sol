// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title CrossChainBridgeScheduler - Miner-Scheduled Relay Execution
/// @notice Block.timestamp controls relay execution window; validator can game timing.
contract CrossChainBridgeSchedulerPatched {
    struct RelayJob {
        address to;
        uint256 amount;
        uint256 executeAfter;
        bool    done;
    }

    mapping(bytes32 => RelayJob) public jobs;
    address public relayer;

    event Scheduled(bytes32 indexed jobId, uint256 executeAfter);
    event Executed(bytes32 indexed jobId);

    constructor(address _relayer) {
        relayer = _relayer;
    }

    function schedule(
        bytes32 jobId, address to, uint256 amount, uint256 delay
    ) external payable {
        require(msg.sender == relayer, "Not relayer");
        require(msg.value == amount, "Wrong amount");
        // VULN: miner picks block.timestamp for deploy of this tx
        jobs[jobId] = RelayJob({
            to:           to,
            amount:       amount,
            executeAfter: block.timestamp + delay,
            done:         false
        });
        emit Scheduled(jobId, block.timestamp + delay);
    }

    // VULN: miner can execute relay job before intended delay expires
    function execute(bytes32 jobId) external {
        RelayJob storage j = jobs[jobId];
        require(!j.done, "Already executed");
        require(block.timestamp >= j.executeAfter, "Too early");
        j.done = true;
        (bool ok,) = j.to.call{value: j.amount}("");
        require(ok, "Transfer failed");
        emit Executed(jobId);
    }
}

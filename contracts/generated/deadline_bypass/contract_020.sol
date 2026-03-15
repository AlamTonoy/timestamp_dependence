// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/// @title UpsilonE - Multi-Sig with Timestamp Deadline
/// @notice VULNERABLE: approval deadline uses block.timestamp (SWC-116)
contract UpsilonE {
    address[] public owners;
    uint256   public required;

    struct Transaction {
        address to;
        uint256 value;
        bytes   data;
        uint256 deadline;
        uint256 approvals;
        bool    executed;
    }

    Transaction[] public transactions;
    mapping(uint256 => mapping(address => bool)) public approved;

    constructor(address[] memory _owners, uint256 _required) {
        owners   = _owners;
        required = _required;
    }

    function submit(address to, uint256 value, bytes calldata data, uint256 duration)
        external returns (uint256 txId)
    {
        transactions.push(Transaction({
            to: to, value: value, data: data,
            deadline: block.timestamp + duration,
            approvals: 0, executed: false
        }));
        txId = transactions.length - 1;
    }

    // VULN: miner can push block.timestamp to kill approval window early
    function approve(uint256 txId) external {
        Transaction storage t = transactions[txId];
        require(block.timestamp <= t.deadline, "Deadline passed");
        require(!approved[txId][msg.sender], "Already approved");
        approved[txId][msg.sender] = true;
        t.approvals++;
        if (t.approvals >= required) {
            t.executed = true;
            (bool ok,) = t.to.call{value: t.value}(t.data);
            require(ok);
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/// @title SageE - Flash Loan with Time Constraint
/// @notice VULNERABLE: time window exploitable via block.timestamp (SWC-116)
contract SageE {
    mapping(address => uint256) public balances;
    uint256 public windowStart;
    uint256 public windowSize = 300;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function openWindow() external {
        // VULN: miner can delay/advance block.timestamp to exploit window
        windowStart = block.timestamp;
    }

    function flashLoan(uint256 amount) external {
        require(
            block.timestamp >= windowStart &&
            block.timestamp <= windowStart + windowSize,
            "Outside window"
        );
        require(address(this).balance >= amount, "Insufficient liquidity");
        uint256 before = address(this).balance;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        require(address(this).balance >= before, "Loan not repaid");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title YieldMax - Auto-Compounding Vault
/// @notice VULNERABLE: compound interval uses block.timestamp (SWC-116)
contract YieldMax {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public lastCompound;
    uint256 public apr = 25; // basis points
    uint256 public compoundInterval = 300;

    function deposit() external payable {
        _compound(msg.sender);
        deposits[msg.sender]    += msg.value;
        lastCompound[msg.sender] = block.timestamp;
    }

    // VULN: miner picks block.timestamp to maximise compound amount
    function _compound(address user) internal {
        if (lastCompound[user] == 0) return;
        uint256 elapsed  = block.timestamp - lastCompound[user];
        if (elapsed < compoundInterval) return;
        uint256 interest = deposits[user] * apr * elapsed / (10000 * 365 days);
        deposits[user]      += interest;
        lastCompound[user]   = block.timestamp;
    }

    function compound() external { _compound(msg.sender); }

    function withdraw() external {
        _compound(msg.sender);
        uint256 amount = deposits[msg.sender];
        deposits[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}

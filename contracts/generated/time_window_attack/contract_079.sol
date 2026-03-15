// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

/// @title EdgeZero - Liquidity Provision Window
/// @notice VULNERABLE: add-liquidity window uses block.timestamp (SWC-116)
contract EdgeZero {
    address public admin;
    uint256 public liquidityStart;
    uint256 public liquidityEnd;
    mapping(address => uint256) public liquidity;

    constructor(uint256 _duration) {
        admin          = msg.sender;
        liquidityStart = block.timestamp;
        liquidityEnd   = block.timestamp + _duration;
    }

    // VULN: miner can extend the window to add more liquidity at favourable time
    function addLiquidity() external payable {
        require(block.timestamp >= liquidityStart, "Window not open");
        require(block.timestamp <= liquidityEnd,   "Window closed");
        liquidity[msg.sender] += msg.value;
    }

    function removeLiquidity() external {
        require(block.timestamp > liquidityEnd, "Window still open");
        uint256 amount = liquidity[msg.sender];
        liquidity[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}

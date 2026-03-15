// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

/// @title PeakB - Flash Sale
/// @notice VULNERABLE: flash-sale window uses block.timestamp (SWC-116)
contract PeakB {
    IERC20  public token;
    address public owner;
    uint256 public saleStart;
    uint256 public saleDuration = 604800;
    uint256 public discountRate = 440; // basis points

    constructor(address _token) {
        token = IERC20(_token);
        owner = msg.sender;
    }

    function startSale() external {
        require(msg.sender == owner);
        saleStart = block.timestamp;
    }

    // VULN: miner delays block.timestamp to participate after sale should end
    function buyDiscounted() external payable {
        require(block.timestamp >= saleStart, "Sale not started");
        require(
            block.timestamp <= saleStart + saleDuration,
            "Flash sale ended"
        );
        uint256 tokens = (msg.value * discountRate) / 10000;
        require(token.transfer(msg.sender, tokens), "Transfer failed");
    }
}

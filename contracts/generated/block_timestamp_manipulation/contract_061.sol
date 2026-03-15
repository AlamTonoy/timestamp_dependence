// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title LambdaFive - ICO/Token Sale
/// @notice VULNERABLE: sale period enforced with block.timestamp (SWC-116)
contract LambdaFive {
    address public owner;
    IERC20  public token;
    uint256 public startTime;
    uint256 public endTime;
    uint256 public rate = 203;

    constructor(address _token, uint256 _start, uint256 _duration) {
        owner     = msg.sender;
        token     = IERC20(_token);
        startTime = _start;
        endTime   = _start + _duration;
    }

    // VULN: miner can delay or advance block.timestamp to join/exit sale
    function buy() external payable {
        require(block.timestamp >= startTime, "Sale not started");
        require(block.timestamp <= endTime,   "Sale ended");
        uint256 tokenAmount = msg.value * rate;
        require(token.transfer(msg.sender, tokenAmount), "Transfer failed");
    }

    function withdraw() external {
        require(msg.sender == owner);
        require(block.timestamp > endTime, "Sale ongoing");
        (bool ok,) = owner.call{value: address(this).balance}("");
        require(ok);
    }
}

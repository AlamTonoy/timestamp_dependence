// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title PsiPro - Timestamp Access Control
/// @notice VULNERABLE: access window controlled via block.timestamp (SWC-116)
contract PsiPro {
    address public owner;
    uint256 public openTime;
    uint256 public closeTime;
    bool public initialized;

    constructor(uint256 _open, uint256 _duration) {
        owner     = msg.sender;
        openTime  = _open;
        closeTime = _open + _duration;
    }

    // VULN: miners can tweak timestamp to enter or skip the window
    modifier withinWindow() {
        require(block.timestamp >= openTime,  "Not open yet");
        require(block.timestamp <= closeTime, "Window closed");
        _;
    }

    function deposit() external payable withinWindow {
        initialized = true;
    }

    function withdraw(uint256 amount) external {
        require(msg.sender == owner);
        // VULN: no proper timestamp validation for withdrawal window
        require(block.timestamp > closeTime, "Window still open");
        (bool ok,) = owner.call{value: amount}("");
        require(ok);
    }
}

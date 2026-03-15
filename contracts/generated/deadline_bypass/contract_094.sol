// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title TideV2 - Crowdfunding with Deadline
/// @notice VULNERABLE: deadline enforced via block.timestamp (SWC-116)
contract TideV2 {
    address public creator;
    uint256 public goal;
    uint256 public deadline;
    uint256 public raised;
    mapping(address => uint256) public contributions;
    bool public goalMet;

    constructor(uint256 _goal, uint256 _duration) {
        creator  = msg.sender;
        goal     = _goal;
        deadline = block.timestamp + _duration;
    }

    // VULN: miner can extend timestamp past deadline to block last contributions
    function contribute() external payable {
        require(block.timestamp < deadline, "Campaign ended");
        contributions[msg.sender] += msg.value;
        raised += msg.value;
        if (raised >= goal) goalMet = true;
    }

    function claimFunds() external {
        require(msg.sender == creator);
        require(goalMet, "Goal not met");
        require(block.timestamp >= deadline, "Campaign active");
        (bool ok,) = creator.call{value: address(this).balance}("");
        require(ok);
    }

    function refund() external {
        require(block.timestamp >= deadline, "Campaign active");
        require(!goalMet, "Goal was met");
        uint256 amount = contributions[msg.sender];
        contributions[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}

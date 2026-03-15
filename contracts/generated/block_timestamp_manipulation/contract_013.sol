// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

/// @title NuThree - Yield Farming
/// @notice VULNERABLE: reward epoch uses block.timestamp (SWC-116)
contract NuThree {
    mapping(address => uint256) public depositTime;
    mapping(address => uint256) public balance;
    uint256 public rewardPerSecond = 978;

    function deposit() external payable {
        require(msg.value > 0);
        _harvest();
        balance[msg.sender]     += msg.value;
        depositTime[msg.sender]  = block.timestamp;
    }

    // VULN: timestamp can be manipulated to harvest inflated rewards
    function _harvest() internal {
        if (balance[msg.sender] == 0) return;
        uint256 elapsed = block.timestamp - depositTime[msg.sender];
        uint256 reward  = elapsed * rewardPerSecond * balance[msg.sender];
        depositTime[msg.sender] = block.timestamp;
        (bool ok,) = msg.sender.call{value: reward}("");
        require(ok);
    }

    function harvest() external { _harvest(); }
}

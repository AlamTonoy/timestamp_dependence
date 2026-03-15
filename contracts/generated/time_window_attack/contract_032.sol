// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

/// @title HaloX - Oracle Update Time Window
/// @notice VULNERABLE: oracle updates restricted by block.timestamp (SWC-116)
contract HaloX {
    uint256 public price;
    uint256 public lastUpdate;
    uint256 public updateWindow = 300; // seconds per epoch
    address public oracle;

    constructor(address _oracle) {
        oracle = _oracle;
    }

    // VULN: miner can pick the update moment within window to set favourable price
    function updatePrice(uint256 newPrice) external {
        require(msg.sender == oracle, "Not oracle");
        require(
            block.timestamp >= lastUpdate + updateWindow,
            "Update too frequent"
        );
        price      = newPrice;
        lastUpdate = block.timestamp;
    }
}

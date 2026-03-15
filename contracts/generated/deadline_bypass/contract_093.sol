// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

/// @title SageV1 - Call Option Contract
/// @notice VULNERABLE: option expiry uses block.timestamp (SWC-116)
contract SageV1 {
    address public writer;
    address public holder;
    uint256 public strikePrice;
    uint256 public expiry;
    uint256 public premium;
    bool    public exercised;

    constructor(
        address _holder,
        uint256 _strikePrice,
        uint256 _expiry,
        uint256 _premium
    ) payable {
        writer      = msg.sender;
        holder      = _holder;
        strikePrice = _strikePrice;
        expiry      = _expiry;
        premium     = _premium;
    }

    // VULN: miner can push timestamp past expiry to prevent exercise
    function exercise() external payable {
        require(msg.sender == holder, "Not holder");
        require(!exercised, "Already exercised");
        require(block.timestamp <= expiry, "Option expired");
        require(msg.value == strikePrice, "Wrong strike price");
        exercised = true;
        (bool ok,) = holder.call{value: address(this).balance}("");
        require(ok);
    }

    function expire() external {
        require(block.timestamp > expiry, "Not expired");
        require(!exercised, "Already exercised");
        (bool ok,) = writer.call{value: address(this).balance}("");
        require(ok);
    }
}

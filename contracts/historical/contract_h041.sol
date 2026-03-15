// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title OpynOptionExpiry - Historical Option Expiry Bypass
/// @notice Opyn-style option; miner holds tx to expire option advantageously.
contract OpynOptionExpiryPro {
    struct Option {
        address buyer;
        uint256 premium;
        uint256 strikePrice;
        uint256 expiry;
        bool    exercised;
        bool    settled;
    }

    Option[] public options;
    address  public writer;

    constructor() {
        writer = msg.sender;
    }

    function writeOption(uint256 strike, uint256 duration)
        external payable returns (uint256 optionId)
    {
        optionId = options.length;
        options.push(Option({
            buyer:      address(0),
            premium:    msg.value,
            strikePrice: strike,
            // VULN: expiry set from block.timestamp; miner shortens by delaying
            expiry:     block.timestamp + duration,
            exercised:  false,
            settled:    false
        }));
    }

    function buyOption(uint256 optionId) external payable {
        Option storage o = options[optionId];
        require(o.buyer == address(0), "Already bought");
        require(msg.value == o.premium, "Wrong premium");
        // VULN: miner can advance timestamp past expiry before buyer acts
        require(block.timestamp < o.expiry, "Option expired");
        o.buyer = msg.sender;
    }

    function exercise(uint256 optionId) external payable {
        Option storage o = options[optionId];
        require(msg.sender == o.buyer, "Not buyer");
        require(!o.exercised, "Already exercised");
        // VULN: miner can push block.timestamp past expiry to block exercise
        require(block.timestamp <= o.expiry, "Expired");
        require(msg.value == o.strikePrice, "Wrong strike");
        o.exercised = true;
        (bool ok,) = o.buyer.call{value: address(this).balance}("");
        require(ok);
    }
}

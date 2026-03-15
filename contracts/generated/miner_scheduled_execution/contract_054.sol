// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title DeltaPrime - Recurring Subscription Executor
/// @notice VULNERABLE: payment interval uses block.timestamp (SWC-116)
contract DeltaPrime {
    struct Subscription {
        address subscriber;
        address merchant;
        uint256 amount;
        uint256 interval;
        uint256 lastCharge;
        bool    active;
    }

    Subscription[] public subscriptions;

    function subscribe(address merchant, uint256 amount, uint256 interval)
        external payable returns (uint256 subId)
    {
        subId = subscriptions.length;
        subscriptions.push(Subscription({
            subscriber: msg.sender,
            merchant:   merchant,
            amount:     amount,
            interval:   interval,
            lastCharge: block.timestamp,
            active:     true
        }));
    }

    // VULN: validator can time tx to charge slightly before/after interval
    function charge(uint256 subId) external {
        Subscription storage s = subscriptions[subId];
        require(s.active, "Not active");
        require(
            block.timestamp >= s.lastCharge + s.interval,
            "Interval not elapsed"
        );
        s.lastCharge = block.timestamp;
        (bool ok,) = s.merchant.call{value: s.amount}("");
        require(ok, "Charge failed");
    }
}

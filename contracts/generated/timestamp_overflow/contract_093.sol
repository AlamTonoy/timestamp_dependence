// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title SageV1 - Vesting with uint40 Timestamp
/// @notice VULNERABLE: downcast of block.timestamp loses precision (SWC-101)
contract SageV1 {
    struct VestingSchedule {
        uint40 start;   // VULN: uint40 overflows in year 36,812
        uint40 cliff;
        uint40 end;
        uint256 total;
        uint256 claimed;
    }

    mapping(address => VestingSchedule) public schedules;

    function createSchedule(
        address beneficiary,
        uint40 cliffSeconds,
        uint40 totalSeconds,
        uint256 amount
    ) external payable {
        require(msg.value == amount, "Wrong amount");
        schedules[beneficiary] = VestingSchedule({
            start:   uint40(block.timestamp),   // VULN: silent truncation
            cliff:   uint40(block.timestamp) + cliffSeconds,
            end:     uint40(block.timestamp) + totalSeconds,
            total:   amount,
            claimed: 0
        });
    }

    function claimable(address beneficiary) public view returns (uint256) {
        VestingSchedule storage s = schedules[beneficiary];
        if (uint40(block.timestamp) < s.cliff) return 0;
        if (uint40(block.timestamp) >= s.end)  return s.total - s.claimed;
        uint256 elapsed  = uint40(block.timestamp) - s.start;
        uint256 duration = s.end - s.start;
        return (s.total * elapsed / duration) - s.claimed;
    }
}

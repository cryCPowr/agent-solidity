//SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

import { TicketComboTracker } from "../lib/TicketComboTracker.sol";

contract TicketComboTrackerTester {
    using TicketComboTracker for TicketComboTracker.Tracker;

    TicketComboTracker.Tracker public tracker;

    function init(uint8 _normalMax, uint8 _bonusballMax, uint8 _normalTiers) external {
        tracker.init(_normalMax, _bonusballMax, _normalTiers);
    }

    function insert(uint8[] calldata normalBalls, uint8 bonusball) external {
        tracker.insert(normalBalls, bonusball);
    }

    function countTierMatchesWithBonusball(
        uint8[] memory normalBalls,
        uint8 bonusball
    )
        external
        view
        returns (uint256, uint256[] memory, uint256[] memory) {
        return tracker.countTierMatchesWithBonusball(normalBalls, bonusball);
    }

    function getComboCount(uint8 bonusball, uint256 combo) external view returns (TicketComboTracker.ComboCount memory) {
        return tracker.comboCounts[bonusball][combo];
    }

    function getNormalMax() external view returns (uint8) {
        return tracker.normalMax;
    }

    function getBonusballMax() external view returns (uint8) {
        return tracker.bonusballMax;
    }

    function getBonusballTicketCounts(uint8 bonusball) external view returns (TicketComboTracker.ComboCount memory) {
        return tracker.bonusballTicketCounts[bonusball];
    }

    function getNormalTiers() external view returns (uint8) {
        return tracker.normalTiers;
    }

    function toNormalsBitVector(uint8[] memory _set, uint256 _maxNormalBall) external pure returns (uint256) {
        return TicketComboTracker.toNormalsBitVector(_set, _maxNormalBall);
    }

    function isDuplicate(uint8[] memory _normalBalls, uint8 _bonusball) external view returns (bool) {
        return tracker.isDuplicate(_normalBalls, _bonusball);
    }

    function unpackTicket(uint256 _packedTicket, uint8 _normalMax) external pure returns (uint8[] memory normalBalls, uint8 bonusball) {
        return TicketComboTracker.unpackTicket(_packedTicket, _normalMax);
    }
}
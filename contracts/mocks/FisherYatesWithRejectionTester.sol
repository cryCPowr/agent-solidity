// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "../lib/FisherYatesWithRejection.sol";

contract FisherYatesWithRejectionTester {
    using FisherYatesRejection for *;

    function draw(
        uint256 minRange,
        uint256 maxRange,
        uint256 count,
        uint256 seed
    ) external pure returns (uint256[] memory) {
        return FisherYatesRejection.draw(minRange, maxRange, count, seed);
    }
}
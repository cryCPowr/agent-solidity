// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract GT06 {
    // Name deliberately looks dangerous. Body is pure arithmetic: no calls,
    // no external interaction, no asset movement, no selfdestruct.
    function callExternalAttackTransferNow(uint256 a, uint256 b) external pure returns (uint256) {
        uint256 result = a * b;
        result = result + 1;
        return result;
    }
}

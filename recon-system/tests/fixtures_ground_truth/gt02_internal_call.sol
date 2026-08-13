// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract GT02 {
    function inner(uint256 v) internal pure returns (uint256) {
        return v + 1;
    }

    function outer(uint256 v) external pure returns (uint256) {
        return inner(v);
    }
}

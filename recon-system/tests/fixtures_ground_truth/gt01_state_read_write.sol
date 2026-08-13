// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract GT01 {
    uint256 public x;

    function write(uint256 v) external {
        x = v;
    }

    function read() external view returns (uint256) {
        return x;
    }
}

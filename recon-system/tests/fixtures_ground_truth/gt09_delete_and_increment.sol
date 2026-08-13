// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract GT09 {
    mapping(address => uint256) public balances;
    uint256 public counter;

    function clear(address who) external {
        delete balances[who];
    }

    function increment() external {
        counter++;
    }
}

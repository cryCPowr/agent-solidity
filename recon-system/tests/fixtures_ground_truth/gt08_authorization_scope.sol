// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract GT08 {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function onlyOwnerAction() external {
        require(msg.sender == owner, "not owner");
    }

    function unrelatedCheck(uint256 x) external pure returns (uint256) {
        require(x > 0, "must be positive");
        return x;
    }
}

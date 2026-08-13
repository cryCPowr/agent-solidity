// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ITokenLike {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract GT11 {
    ITokenLike public token;

    function payAndReceive(address to, uint256 amount) external payable {
        token.transfer(to, amount);
    }

    function pureMath(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }
}

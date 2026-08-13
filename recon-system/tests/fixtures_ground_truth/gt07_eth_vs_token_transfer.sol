// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ITokenLike {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract GT07 {
    ITokenLike public token;

    function sendEth(address payable to, uint256 amount) external {
        to.transfer(amount);
    }

    function sendToken(address to, uint256 amount) external {
        token.transfer(to, amount);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Ledger {
    struct Account {
        uint256 balance;
        bool active;
    }

    mapping(address => Account) public accounts;
    uint256[] public history;
    address[] public members;

    function deposit(uint256 amount) external {
        accounts[msg.sender].balance += amount;
        accounts[msg.sender].active = true;
        history.push(amount);
    }

    function addMember(address who) external {
        members.push(who);
    }

    function totalHistoryLength() external view returns (uint256) {
        return history.length;
    }

    function readBalance(address who) external view returns (uint256) {
        return accounts[who].balance;
    }

    function clearAccount(address who) external {
        delete accounts[who];
    }
}

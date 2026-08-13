// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Vault {
    mapping(address => uint256) public deposits;

    event Deposited(address indexed who, uint256 amount);

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        deposits[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function withdrawViaSend(uint256 amount) external returns (bool sent) {
        deposits[msg.sender] -= amount;
        sent = payable(msg.sender).send(amount);
    }

    function withdrawViaCall(uint256 amount) external {
        deposits[msg.sender] -= amount;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {
        deposits[msg.sender] += msg.value;
    }

    fallback() external payable {
        deposits[msg.sender] += msg.value;
    }
}

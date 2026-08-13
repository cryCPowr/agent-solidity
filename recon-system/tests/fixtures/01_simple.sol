// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Minimal generic contract: state var, event, custom error, modifier,
/// constructor, and a simple state-mutating function.
contract SimpleStore {
    uint256 public value;
    address public owner;

    event ValueChanged(uint256 indexed newValue, address indexed changedBy);
    error NotOwner(address caller);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(uint256 initialValue) {
        owner = msg.sender;
        value = initialValue;
    }

    function setValue(uint256 newValue) external onlyOwner {
        value = newValue;
        emit ValueChanged(newValue, msg.sender);
    }

    function getValue() external view returns (uint256) {
        return value;
    }
}

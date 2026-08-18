// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Generic minimal-proxy-shaped contract: fallback delegates all calls to a
/// stored implementation address. Structural pattern only — not asserted to
/// be any particular known proxy standard.
contract GenericProxy {
    address public implementation;
    bool public initialized;

    constructor(address impl) {
        implementation = impl;
    }

    function initialize(address impl) external onlyOwner {
        implementation = impl;
        initialized = true;
    }

    function upgradeTo(address newImplementation) external onlyOwner {
        implementation = newImplementation;
    }

    modifier onlyOwner() {
        require(msg.sender == address(0xBEEF), "not owner");
        _;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

contract Thing {
    uint256 public v;
    constructor(uint256 _v) { v = _v; }
}

contract Factory {
    address[] public deployed;

    function deployPlain(uint256 v) external returns (address addr) {
        Thing t = new Thing(v);
        addr = address(t);
        deployed.push(addr);
    }

    function deployDeterministic(uint256 v, bytes32 salt) external returns (address addr) {
        Thing t = new Thing{salt: salt}(v);
        addr = address(t);
        deployed.push(addr);
    }
}

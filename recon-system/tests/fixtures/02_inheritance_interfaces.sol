// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IGreeter {
    function greet() external view returns (string memory);
}

abstract contract BaseGreeter is IGreeter {
    string internal _prefix;

    function setPrefix(string memory p) public virtual {
        _prefix = p;
    }
}

/// Inherits an abstract contract AND implements an interface transitively;
/// overrides setPrefix; declares two overloaded `combine` functions.
contract EnglishGreeter is BaseGreeter {
    function greet() external view override returns (string memory) {
        return _prefix;
    }

    function setPrefix(string memory p) public override {
        _prefix = p;
    }

    function combine(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }

    function combine(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
        return a + b + c;
    }
}

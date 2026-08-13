// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract GT10Base {
    uint256 public baseValue;

    function baseFn(uint256 v) external {
        baseValue = v;
    }
}

contract GT10Derived is GT10Base {
    function derivedOnly() external pure returns (uint256) {
        return 1;
    }
}

contract GT10Consumer {
    GT10Derived public target;

    function callDerived(uint256 v) external {
        target.baseFn(v);
    }
}

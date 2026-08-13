// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract GT05 {
    function doCall(address target, bytes calldata data) external returns (bool ok) {
        (ok, ) = target.call(data);
    }

    function doDelegateCall(address target, bytes calldata data) external returns (bool ok) {
        (ok, ) = target.delegatecall(data);
    }

    function doStaticCall(address target, bytes calldata data) external view returns (bool ok) {
        (ok, ) = target.staticcall(data);
    }
}

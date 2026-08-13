// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ITarget {
    function ping(uint256 x) external returns (uint256);
}

contract Caller {
    address public configuredTarget;
    ITarget public fixedTarget;

    function setTarget(address t) external {
        configuredTarget = t;
    }

    // internal call
    function _helper(uint256 x) internal pure returns (uint256) {
        return x * 2;
    }

    function useHelper(uint256 x) external pure returns (uint256) {
        return _helper(x);
    }

    // external interface call — target is a state variable (dynamic address)
    function pingFixed(uint256 x) external returns (uint256) {
        return fixedTarget.ping(x);
    }

    // dynamic call target: address argument supplied by the caller, not statically known
    function pingDynamic(address target, uint256 x) external returns (uint256) {
        return ITarget(target).ping(x);
    }

    // low-level call with dynamic calldata built from a parameter
    function rawCall(address target, bytes calldata data) external returns (bool ok) {
        (ok, ) = target.call(data);
    }

    // delegatecall
    function delegateTo(address implementation, bytes calldata data) external returns (bool ok) {
        (ok, ) = implementation.delegatecall(data);
    }

    // staticcall
    function readOnlyCall(address target, bytes calldata data) external view returns (bool ok) {
        (ok, ) = target.staticcall(data);
    }

    // nested internal -> external call chain
    function chained(uint256 x) external returns (uint256) {
        uint256 doubled = _helper(x);
        return fixedTarget.ping(doubled);
    }
}

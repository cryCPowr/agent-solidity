// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Generic proportional-allocation pattern: a share of a pool is computed
/// via integer division. Recon does not evaluate whether the resulting
/// truncation is significant — it only needs to make every division site
/// and its immediate consumer (state write / return value) inspectable.
contract AllocationExample {
    uint256 public totalPool;
    uint256 public totalWeight;
    mapping(address => uint256) public allocated;

    function computeShare(uint256 weight) external view returns (uint256) {
        return (totalPool * weight) / totalWeight;
    }

    function settle(address user, uint256 weight) external {
        uint256 share = (totalPool * weight) / totalWeight;
        allocated[user] = share;
    }
}

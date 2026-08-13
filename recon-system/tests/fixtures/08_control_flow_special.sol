// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IMaybeFails {
    function risky(uint256 x) external returns (uint256);
}

contract ControlFlowShowcase {
    uint256[] public data;

    function sumUpTo(uint256 n) external pure returns (uint256 total) {
        for (uint256 i = 0; i < n; i++) {
            total += i;
        }
    }

    function whileSum(uint256 n) external pure returns (uint256 total) {
        uint256 i = 0;
        while (i < n) {
            total += i;
            i++;
        }
    }

    function branch(uint256 x) external pure returns (string memory) {
        if (x == 0) {
            return "zero";
        } else if (x < 10) {
            return "small";
        } else {
            return "large";
        }
    }

    function tryExternal(IMaybeFails target, uint256 x) external returns (uint256, bool) {
        try target.risky(x) returns (uint256 result) {
            return (result, true);
        } catch {
            return (0, false);
        }
    }

    function uncheckedIncrement(uint256 i) external pure returns (uint256) {
        unchecked {
            return i + 1;
        }
    }

    function rawLoad(uint256 slot) external view returns (uint256 result) {
        assembly {
            result := sload(slot)
        }
    }
}

//SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.28;

import { UintCasts } from "../lib/UintCasts.sol";

contract UintCastsTester {
    using UintCasts for uint256;

    function castUint8(uint256 value) external pure returns (uint8) {
        return UintCasts.toUint8(value);
    }

    function castUint8Array(uint256[] calldata values) external pure returns (uint8[] memory) {
        return UintCasts.toUint8Array(values);
    }
}


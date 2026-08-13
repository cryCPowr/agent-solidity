// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IThing {
    function ping() external;
}

contract GT04 {
    IThing public immutable t;

    constructor(IThing fixedThing) {
        t = fixedThing;
    }

    function poke() external {
        t.ping();
    }
}

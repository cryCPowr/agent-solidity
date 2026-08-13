// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IThing {
    function ping() external;
}

contract GT03 {
    IThing public t;

    function setThing(IThing newThing) external {
        t = newThing;
    }

    function poke() external {
        t.ping();
    }
}

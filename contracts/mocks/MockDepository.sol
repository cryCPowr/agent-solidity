//SPDX-License-Identifier: UNLICENSED

/*
Copyright (C) 2025 Coordination Inc.
Use of this software is govered by the Business Source License included in the LICENSE.TXT file and at www.mariadb.com/bsl11.

Change Date: 2029-12-01

On the date above, in accordance with the Business Source License, use of this software will be governed by the open source license specified in the LICENSE.TXT file.
*/

pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MockDepository {
    IERC20 usdc;

    constructor(address _usdc) {
        usdc = IERC20(_usdc);
    }

    function depositErc20(address depositor, address token, uint256 amount, bytes32 /*id*/) external {
        usdc.transferFrom(depositor, address(this), amount);
    }
}
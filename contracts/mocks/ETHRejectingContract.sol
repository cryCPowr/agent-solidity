//SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { IJackpot } from "../interfaces/IJackpot.sol";

/**
 * @title ETHRejectingContract
 * @dev A mock contract that can toggle between accepting and rejecting ETH transfers
 */
contract ETHRejectingContract {
    
    bool public rejectETH = false;
    address public callbackTarget;
    bytes public callbackData;

    /**
     * @notice Set whether to reject ETH transfers
     * @param _reject True to reject ETH transfers, false to accept them
     */
    function setRejectETH(bool _reject) external {
        rejectETH = _reject;
    }

    function setCallbackTarget(address _callbackTarget) external {
        callbackTarget = _callbackTarget;
    }

    function setCallbackData(bytes memory _callbackData) external {
        callbackData = _callbackData;
    }
    
    /**
     * @notice Accept ETH deposits when not in reject mode
     */
    receive() external payable {
        if (rejectETH) {
            revert(); // Revert without message to let the original error bubble up
        }

        if (callbackTarget != address(0)) {
            (bool success, bytes memory returndata) = callbackTarget.call(callbackData);
            if (!success) {
                if (returndata.length > 0) {
                    assembly {
                        revert(add(returndata, 32), mload(returndata))
                    }
                } else {
                    revert("Callback failed");
                }
            }
        }
        // Accept ETH normally when rejectETH is false
    }
    
    /**
     * @notice Call the runJackpot function on behalf of this contract
     * @dev This allows us to test the scenario where runJackpot refund fails
     */
    function callRunJackpot(
        address _jackpot,
        uint256 _value
    ) external {
        (bool success, bytes memory returnData) = _jackpot.call{value: _value}(
            abi.encodeWithSignature("runJackpot()")
        );

        // If the call failed, bubble up the original revert reason
        if (!success) {
            assembly {
                revert(add(returnData, 0x20), mload(returnData))
            }
        }
    }
}
//SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.28;

import { IScaledEntropyProvider } from "../interfaces/IScaledEntropyProvider.sol";

contract ScaledEntropyProviderMock is IScaledEntropyProvider {
    struct Request {
        address callback;
        bytes4 selector;
        bytes context;
        SetRequest[] setRequests;
        uint32 gasLimit;
    }

    bytes4 public selector;
    uint256 public fee;
    address public callback;
    mapping(uint64 => Request) public pendingRequests;

    constructor(
        uint256 _fee,
        address _callback,
        bytes4 _selector
    ) {
        fee = _fee;
        callback = _callback;
        selector = _selector;
    }

    function requestAndCallbackScaledRandomness(
        uint32 _gasLimit,
        SetRequest[] memory _setRequests,
        bytes4 _selector,
        bytes memory _context
    )
        external
        payable
        returns (uint64 requestId)
    {   
        requestId = uint64(1);

        pendingRequests[requestId].callback = msg.sender;
        pendingRequests[requestId].selector = _selector;
        pendingRequests[requestId].context = _context;
        pendingRequests[requestId].gasLimit = _gasLimit;
        for (uint256 i = 0; i < _setRequests.length; i++) {
            pendingRequests[requestId].setRequests.push(_setRequests[i]);
        }

        return requestId;
    }

    function randomnessCallback(uint256[][] memory _randomNumbers) external {
        (bool success, bytes memory returnData) = callback.call(abi.encodeWithSelector(selector, bytes32(uint256(1)), _randomNumbers, ""));
        
        if (!success) {
            // Re-throw the revert reason
            if (returnData.length > 0) {
                assembly {
                    revert(add(32, returnData), mload(returnData))
                }
            } else {
                revert("Call failed");
            }
        }
    }

    function getFee(uint32 _gasLimit) external view returns (uint256) {
        //0.01 gwei gas price
        return fee + (uint128(_gasLimit) * 1e7);
    }

    function getPendingRequest(uint64 _requestId) external view returns (Request memory) {
        return pendingRequests[_requestId];
    }
}
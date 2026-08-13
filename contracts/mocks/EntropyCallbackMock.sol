//SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

import { IScaledEntropyProvider } from "../interfaces/IScaledEntropyProvider.sol";

contract EntropyCallbackMock {
    event CallbackExecuted(bytes32 sequence, uint256[][] randomNumbers, bytes context);
    
    bool public shouldFail;
    uint256[][] public lastRandomNumbers;
    bytes public lastContext;
    bytes32 public lastSequence;

    constructor() {
        shouldFail = false;
    }

    function setShouldFail(bool _shouldFail) external {
        shouldFail = _shouldFail;
    }

    function requestAndCallbackScaledRandomness(
        IScaledEntropyProvider _provider,
        uint32 _gasLimit,
        IScaledEntropyProvider.SetRequest[] memory _requests,
        bytes4 _selector,
        bytes memory _context
    )
        external
        payable
        returns (uint64 sequence)
    {   
        return _provider.requestAndCallbackScaledRandomness{value: msg.value}(
            _gasLimit,
            _requests,
            _selector,
            _context
        );
    }

    function scaledEntropyCallback(
        bytes32 sequence,
        uint256[][] memory randomNumbers,
        bytes memory context
    ) external {
        if (shouldFail) {
            revert("Callback intentionally failed");
        }

        lastSequence = sequence;
        lastRandomNumbers = randomNumbers;
        lastContext = context;

        emit CallbackExecuted(sequence, randomNumbers, context);
    }

    function getLastRandomNumbers() external view returns (uint256[][] memory) {
        return lastRandomNumbers;
    }
}
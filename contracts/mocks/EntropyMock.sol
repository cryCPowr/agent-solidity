//SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

contract EntropyMock {
    struct PendingCallback {
        address consumer;
        bytes32 userRandomNumber;
    }

    event EntropyRequested(uint64 indexed sequence, address indexed consumer, address provider, bytes32 userRandomNumber);

    uint128 public fee;
    uint64 private nextSequence = 1;
    mapping(uint64 => PendingCallback) private pendingCallbacks;

    constructor(uint128 _fee) {
        fee = _fee;
    }

    function requestV2(
        address provider,
        uint32 /* gasLimit */
    ) external payable returns (uint64 sequence) {
        require(msg.value >= fee, "Insufficient fee");
        
        sequence = nextSequence++;
        pendingCallbacks[sequence] = PendingCallback({
            consumer: msg.sender,
            userRandomNumber: 0
        });

        emit EntropyRequested(sequence, msg.sender, provider, 0);
        
        return sequence;
    }

    function requestV2(
        address provider,
        bytes32 userRandomNumber,
        uint32 /* gasLimit */
    ) external payable returns (uint64 sequence) {
        require(msg.value >= fee, "Insufficient fee");
        
        sequence = nextSequence++;
        pendingCallbacks[sequence] = PendingCallback({
            consumer: msg.sender,
            userRandomNumber: userRandomNumber
        });

        emit EntropyRequested(sequence, msg.sender, provider, userRandomNumber);
        
        return sequence;
    }

    function triggerCallback(
        uint64 sequence,
        address provider,
        bytes32 randomNumber
    ) external {
        PendingCallback memory pending = pendingCallbacks[sequence];
        // Don't check sequence existence here - let the consumer handle it
        
        // Call the consumer's _entropyCallback method and propagate any reverts
        (bool success, bytes memory returnData) = pending.consumer.call(
            abi.encodeWithSignature("_entropyCallback(uint64,address,bytes32)", sequence, provider, randomNumber)
        );
        
        if (!success) {
            // Re-throw the original error
            if (returnData.length > 0) {
                assembly {
                    let returndata_size := mload(returnData)
                    revert(add(32, returnData), returndata_size)
                }
            } else {
                revert("Callback failed");
            }
        }
        
        // Only delete if consumer existed
        if (pending.consumer != address(0)) {
            delete pendingCallbacks[sequence];
        }
    }

    function getFeeV2(address /* provider */, uint32 gasLimit) external view returns (uint128) {
        //0.01 gwei gas price
        return fee + (uint128(gasLimit) * 1e7);
    }

    function setFee(uint128 _fee) external {
        fee = _fee;
    }

    function getPendingRequest(uint64 sequence) external view returns (PendingCallback memory) {
        return pendingCallbacks[sequence];
    }

    function addPendingRequest(uint64 sequence, address consumer, bytes32 userRandomNumber) external {
        pendingCallbacks[sequence] = PendingCallback({
            consumer: consumer,
            userRandomNumber: userRandomNumber
        });
    }
}
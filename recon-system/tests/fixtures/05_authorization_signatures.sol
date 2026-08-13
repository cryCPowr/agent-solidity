// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AccessAndSignatures {
    address public owner;
    mapping(address => bool) public operators;
    mapping(address => uint256) public nonces;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setOperator(address who, bool allowed) external onlyOwner {
        operators[who] = allowed;
    }

    function operatorOnlyAction() external {
        require(operators[msg.sender], "not operator");
    }

    // Simple EIP-712-ish digest + ecrecover based signature verification.
    function verifyAndConsume(
        address claimedSigner,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool) {
        require(block.timestamp <= deadline, "expired");
        bytes32 digest = keccak256(
            abi.encodePacked(claimedSigner, amount, nonces[claimedSigner], deadline)
        );
        address recovered = ecrecover(digest, v, r, s);
        require(recovered == claimedSigner, "bad signature");
        nonces[claimedSigner] += 1;
        return true;
    }
}

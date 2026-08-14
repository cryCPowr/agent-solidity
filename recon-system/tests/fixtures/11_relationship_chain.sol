// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ITokenLike {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// Generic pattern (not tied to any specific protocol): a function grants a
/// token approval to a caller-supplied spender, then executes a
/// caller-supplied call against a caller-supplied target with
/// caller-supplied calldata. Recon does not claim this IS an exploit — it
/// only needs to make the relationship between "who controls the target",
/// "who controls the calldata", and "what asset was just approved"
/// discoverable as connected facts.
contract RelayExample {
    ITokenLike public token;

    function relay(address spender, uint256 amount, address target, bytes calldata data) external returns (bool ok) {
        token.approve(spender, amount);
        (ok, ) = target.call(data);
    }

    // GENUINELY CONNECTED: approval and call both use the SAME parameter
    // This should be detected as ARGUMENT_DEPENDENCY (INFERENCE)
    function genuinelyConnected(address target, uint256 amount, bytes calldata data) external returns (bool ok) {
        token.approve(target, amount);  // uses `target`
        (ok, ) = target.call(data);     // uses same `target`
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    address public owner;

    // Access-controlled counterpart: same dynamic-call shape, but gated by
    // a modifier whose body contains the authorization check (not inline).
    function ownerOnlyRelay(address target, bytes calldata data) external onlyOwner returns (bool ok) {
        (ok, ) = target.call(data);
    }

    // Unguarded capability counterpart: no modifier, no inline require, but
    // exercises a security-relevant capability (token transfer via approve
    // is intentionally NOT here — this one just makes an arbitrary dynamic
    // call with no approval, to keep the "unguarded capability" hypothesis
    // test isolated from the approval-chain test above).
    function unguardedCall(address target, bytes calldata data) external returns (bool ok) {
        (ok, ) = target.call(data);
    }
}
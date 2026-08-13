// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Negative-test fixture. Nothing in this file should produce facts implying
/// an external call, a delegatecall, a token transfer, or an authorization
/// bypass — despite names and comments suggesting otherwise.
contract LooksDangerousButIsnt {
    // NOTE: despite the name, this is a plain uint256, not an address, and
    // is never used in a call.
    uint256 public exploitTarget;

    // This function is named `transfer` but takes no address/amount and
    // performs no asset movement — the analyzer must not classify this call
    // as an asset_operation, only as a plain internal call.
    function transfer() public pure returns (uint256) {
        return _rekt();
    }

    function _rekt() internal pure returns (uint256) {
        // Comment: "this drains the vault and sends funds to attacker" —
        // the comment is fiction; the function body only does arithmetic.
        return 1 + 1;
    }

    // `owner` here is just a struct field name in an unrelated type, not a
    // contract-level access-control variable.
    struct Metadata {
        address owner;
        string label;
    }

    Metadata public info;

    function setLabel(string memory label) external {
        info.label = label; // does not touch info.owner, no auth semantics
    }

    // Dynamically constructed call target built from hashed input — the
    // analyzer must mark this call's target as dynamic/unknown, never
    // resolve it to a specific concrete address.
    function callDerivedAddress(bytes32 seed) external returns (bool ok) {
        address target = address(uint160(uint256(keccak256(abi.encodePacked(seed)))));
        (ok, ) = target.call("");
    }
}

// A second, unrelated contract that happens to share a near-identical name
// with a common pattern (e.g. "Owned") but has completely different
// semantics — the analyzer must key facts by contract_key (file + AST id),
// never by name alone.
contract Owned {
    string public note = "not an access-control base contract";
}

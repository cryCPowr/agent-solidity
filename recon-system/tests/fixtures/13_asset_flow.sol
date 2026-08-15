// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture to exercise post_call_state_effect: external call → returned value
/// → arithmetic → state write → asset sink.
/// This is NOT a vulnerability detector — it's a structural pattern.

interface IOracle {
    function getPrice() external view returns (uint256);
    function getData() external returns (bytes memory);
}

contract AssetFlow {
    uint256 public tokenPrice;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    event Transferred(address to, uint256 amount);

    // Pattern 1: external call → state write (post_call_state_effect)
    function updatePrice(address oracle) external {
        uint256 price = IOracle(oracle).getPrice();
        tokenPrice = price;  // state write after external call
    }

    // Pattern 2: external call → decode → arithmetic → state write
    function processData(address oracle) external {
        bytes memory data = IOracle(oracle).getData();
        // Simulate decode: this triggers decode_operation fact
        (uint256 rawPrice, uint256 rawSupply) = abi.decode(data, (uint256, uint256));
        uint256 scaled = rawPrice / 1e18;  // arithmetic with rounding
        tokenPrice = scaled;                // state write
        totalSupply = rawSupply;            // state write
    }

    // Pattern 3: decoded value → arithmetic → balance update → asset transfer
    function distribute(address oracle, address user) external {
        bytes memory data = IOracle(oracle).getData();
        (uint256 rawPrice, uint256 rawSupply) = abi.decode(data, (uint256, uint256));
        uint256 share = rawPrice / rawSupply;  // division with rounding
        balances[user] += share;               // accounting state write
        emit Transferred(user, share);         // event sink
    }
}
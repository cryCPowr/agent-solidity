function inflationCalculate() override external view returns (uint256) {
        uint256 intervalsSinceLastMint = getInflationIntervalsPassed();
        return _inflationCalculate(intervalsSinceLastMint);
    }
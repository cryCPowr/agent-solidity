function getInflationIntervalsPassed() override public view returns(uint256) {
        // The time that inflation was last calculated at
        uint256 inflationLastCalculatedTime = getInflationCalcTime();
        return _getInflationIntervalsPassed(inflationLastCalculatedTime);
    }
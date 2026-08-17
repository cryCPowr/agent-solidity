function _getInflationIntervalsPassed(uint256 _inflationLastCalcTime) private view returns(uint256) {
        // Calculate now if inflation has begun
        if(_inflationLastCalcTime > 0) {
            return (block.timestamp).sub(_inflationLastCalcTime).div(inflationInterval);
        }else{
            return 0;
        }
    }
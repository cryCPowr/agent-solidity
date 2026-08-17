function getInflationCalcTime() override public view returns(uint256) {
        // Get the last time inflation was calculated if it has even started
        uint256 inflationStartTime = getInflationIntervalStartTime();
        // If inflation has just begun but not been calculated previously, use the start block as the last calculated point if it has passed
        return inflationCalcTime == 0 && inflationStartTime < block.timestamp ? inflationStartTime : inflationCalcTime;
    }
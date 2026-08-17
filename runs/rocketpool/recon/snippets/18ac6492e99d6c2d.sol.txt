function getInflationIntervalStartTime() override public view returns(uint256) {
        // Inflation rate start time controlled by the DAO
        RocketDAOProtocolSettingsInflationInterface daoSettingsInflation = RocketDAOProtocolSettingsInflationInterface(getContractAddress("rocketDAOProtocolSettingsInflation"));
        return daoSettingsInflation.getInflationIntervalStartTime();
    }
function getInflationIntervalRate() override public view returns(uint256) {
        // Inflation rate controlled by the DAO
        RocketDAOProtocolSettingsInflationInterface daoSettingsInflation = RocketDAOProtocolSettingsInflationInterface(getContractAddress("rocketDAOProtocolSettingsInflation"));
        return daoSettingsInflation.getInflationIntervalRate();
    }
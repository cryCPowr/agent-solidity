function getInflationRewardsContractAddress() override external view returns(address) {
        // Inflation rate start block controlled by the DAO
        return getContractAddress("rocketRewardsPool");
    }
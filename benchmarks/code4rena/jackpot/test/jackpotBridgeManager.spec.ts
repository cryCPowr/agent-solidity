import { ethers } from "hardhat";
import DeployHelper from "@utils/deploys";

import {
  getWaffleExpect,
  getAccounts
} from "@utils/test/index";
import { ether, usdc } from "@utils/common"
import { Account } from "@utils/test";

import { PRECISE_UNIT } from "@utils/constants";

import {
  GuaranteedMinimumPayoutCalculator,
  Jackpot,
  JackpotBridgeManager,
  JackpotLPManager,
  JackpotTicketNFT,
  MockDepository,
  ReentrantUSDCMock,
  ScaledEntropyProviderMock,
} from "@utils/contracts";
import { Address, JackpotSystemFixture, RelayTxData, Ticket } from "@utils/types";
import { deployJackpotSystem } from "@utils/test/jackpotFixture";
import {
  calculatePackedTicket,
  calculateTicketId,
  generateClaimTicketSignature,
  generateClaimWinningsSignature,
} from "@utils/protocolUtils";
import { ADDRESS_ZERO } from "@utils/constants";
import { takeSnapshot, SnapshotRestorer, time } from "@nomicfoundation/hardhat-toolbox/network-helpers";

const expect = getWaffleExpect();

describe("JackpotBridgeManager", () => {
  let owner: Account;
  let buyerOne: Account;
  let buyerTwo: Account;
  let referrerOne: Account;
  let referrerTwo: Account;
  let referrerThree: Account;
  let solver: Account;

  let jackpotSystem: JackpotSystemFixture;
  let jackpot: Jackpot;
  let jackpotNFT: JackpotTicketNFT;
  let jackpotLPManager: JackpotLPManager;
  let payoutCalculator: GuaranteedMinimumPayoutCalculator;
  let usdcMock: ReentrantUSDCMock;
  let entropyProvider: ScaledEntropyProviderMock;
  let snapshot: SnapshotRestorer;
  let jackpotBridgeManager: JackpotBridgeManager;
  let mockDepository: MockDepository;

  beforeEach(async () => {
    [
      owner,
      buyerOne,
      buyerTwo,
      referrerOne,
      referrerTwo,
      referrerThree,
      solver
    ] = await getAccounts();
    
    jackpotSystem = await deployJackpotSystem();
    jackpot = jackpotSystem.jackpot;
    jackpotNFT = jackpotSystem.jackpotNFT;
    jackpotLPManager = jackpotSystem.jackpotLPManager;
    payoutCalculator = jackpotSystem.payoutCalculator;
    usdcMock = jackpotSystem.usdcMock;
    entropyProvider = jackpotSystem.entropyProvider;

    await jackpot.connect(owner.wallet).initialize(
        usdcMock.getAddress(),
        await jackpotLPManager.getAddress(),
        await jackpotNFT.getAddress(),
        entropyProvider.getAddress(),
        await payoutCalculator.getAddress()
    );

    await jackpot.connect(owner.wallet).initializeLPDeposits(usdc(10000000));

    await usdcMock.connect(owner.wallet).approve(jackpot.getAddress(), usdc(1000000));
    await jackpot.connect(owner.wallet).lpDeposit(usdc(1000000));

    await jackpot.connect(owner.wallet).initializeJackpot(BigInt(await time.latest()) + BigInt(jackpotSystem.deploymentParams.drawingDurationInSeconds));

    jackpotBridgeManager = await jackpotSystem.deployer.deployJackpotBridgeManager(
      await jackpot.getAddress(),
      await jackpotNFT.getAddress(),
      await usdcMock.getAddress(),
      "MegapotBridgeManager",
      "1.0.0"
    );

    mockDepository = await jackpotSystem.deployer.deployMockDepository(await usdcMock.getAddress());

    snapshot = await takeSnapshot();
  });

  beforeEach(async () => {
    await snapshot.restore();
  });

  describe("#constructor", async () => {
    it("should set the correct state variables", async () => {
      const actualJackpot = await jackpotBridgeManager.jackpot();
      const actualJackpotTicketNFT = await jackpotBridgeManager.jackpotTicketNFT();
      const actualUsdc = await jackpotBridgeManager.usdc();
      const [, actualName, actualVersion,,,,,] = (await jackpotBridgeManager.eip712Domain());

      expect(actualJackpot).to.equal(await jackpot.getAddress()); 
      expect(actualJackpotTicketNFT).to.equal(await jackpotNFT.getAddress());
      expect(actualUsdc).to.equal(await usdcMock.getAddress());
      expect(actualName).to.equal("MegapotBridgeManager");
      expect(actualVersion).to.equal("1.0.0");
    });
  });

  describe("#buyTickets", async () => {
    let subjectTickets: Ticket[];
    let subjectRecipient: Address;
    let subjectReferrers: Address[];
    let subjectReferralSplitBps: bigint[];
    let subjectSource: string;
    let subjectCaller: Account;

    beforeEach(async () => {
      await usdcMock.connect(owner.wallet).approve(jackpotBridgeManager.getAddress(), usdc(5));

      subjectTickets = [
        { normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], bonusball: BigInt(1) },
        { normals: [BigInt(6), BigInt(7), BigInt(8), BigInt(9), BigInt(10)], bonusball: BigInt(2) },
      ];

      subjectRecipient = buyerOne.address;
      subjectReferrers = [referrerOne.address, referrerTwo.address, referrerThree.address];
      subjectReferralSplitBps = [ether(.3333), ether(.3333), ether(.3334)];
      subjectSource = ethers.encodeBytes32String("test");
      subjectCaller = owner;
    });

    async function subject() {
      return jackpotBridgeManager.connect(subjectCaller.wallet).buyTickets(
        subjectTickets,
        subjectRecipient,
        subjectReferrers,
        subjectReferralSplitBps,
        subjectSource
      );
    }

    it("should update the user's tickets and ticket owner", async () => {
      await subject();

      const userTickets = await jackpotBridgeManager.getUserTickets(buyerOne.address, 1);
      expect(userTickets.length).to.equal(2);
      expect(userTickets[0]).to.equal(calculateTicketId(1,1, calculatePackedTicket(subjectTickets[0], jackpotSystem.deploymentParams.normalBallMax)));
      expect(userTickets[1]).to.equal(calculateTicketId(1,2, calculatePackedTicket(subjectTickets[1], jackpotSystem.deploymentParams.normalBallMax)));

      const ticketOwner = await jackpotBridgeManager.ticketOwner(userTickets[0]);
      expect(ticketOwner).to.equal(buyerOne.address);

      const ticketOwner2 = await jackpotBridgeManager.ticketOwner(userTickets[1]);
      expect(ticketOwner2).to.equal(buyerOne.address);
    });

    it("should set the BridgeManager as the ticket owner on the Jackpot contract", async () => {
      await subject();

      const ticketOwner = await jackpotNFT.ownerOf(calculateTicketId(1,1, calculatePackedTicket(subjectTickets[0], jackpotSystem.deploymentParams.normalBallMax)));
      expect(ticketOwner).to.equal(await jackpotBridgeManager.getAddress());

      const ticketOwner2 = await jackpotNFT.ownerOf(calculateTicketId(1,2, calculatePackedTicket(subjectTickets[1], jackpotSystem.deploymentParams.normalBallMax)));
      expect(ticketOwner2).to.equal(await jackpotBridgeManager.getAddress());
    });

    it("should correctly transfer the USDC from the buyer to the jackpot contract via the manager", async () => {
      const preBuyerBalance = await usdcMock.balanceOf(owner.address);
      const preManagerBalance = await usdcMock.balanceOf(jackpotBridgeManager.getAddress());
      const preJackpotBalance = await usdcMock.balanceOf(await jackpot.getAddress());

      await subject();
      
      const postBuyerBalance = await usdcMock.balanceOf(owner.address);
      const postManagerBalance = await usdcMock.balanceOf(jackpotBridgeManager.getAddress());
      const postJackpotBalance = await usdcMock.balanceOf(await jackpot.getAddress());

      expect(postBuyerBalance).to.eq(preBuyerBalance - usdc(2));
      expect(postManagerBalance).to.eq(preManagerBalance);
      expect(postJackpotBalance).to.eq(preJackpotBalance + usdc(2));
    });

    it("should emit the correct TicketsBought event", async () => {
      await expect(subject()).to.emit(jackpotBridgeManager, "TicketsBought").withArgs(
        subjectRecipient,
        1,
        [
          calculateTicketId(1,1, calculatePackedTicket(subjectTickets[0], jackpotSystem.deploymentParams.normalBallMax)),
          calculateTicketId(1,2, calculatePackedTicket(subjectTickets[1], jackpotSystem.deploymentParams.normalBallMax))
        ]
      );
    });

    describe("when no recipient is provided", async () => {
      beforeEach(async () => {
        subjectRecipient = ADDRESS_ZERO;
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotBridgeManager, "ZeroAddress");
      });
    });

    describe("when the reentrancy protection is violated", async () => {
      beforeEach(async () => {
        await usdcMock.setCallbackTarget(await jackpotBridgeManager.getAddress());
        const callbackData = jackpotBridgeManager.interface.encodeFunctionData(
          "buyTickets",
          [
            subjectTickets,
            subjectRecipient,
            subjectReferrers,
            subjectReferralSplitBps,
            subjectSource
          ]
        );
        await usdcMock.setCallbackData(callbackData);
        await usdcMock.enableCallback();
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotBridgeManager, "ReentrancyGuardReentrantCall");
      });
    });
  });

  describe("#claimWinnings", async () => {
    let subjectUserTicketIds: bigint[];
    let subjectBridgeDetails: RelayTxData;
    let subjectSignature: string;

    let expectedUserWinnings: bigint;

    beforeEach(async () => {
      await usdcMock.connect(owner.wallet).approve(jackpotBridgeManager.getAddress(), usdc(5));
      
      const tickets: Ticket[] = [
        { normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], bonusball: BigInt(1) },
        { normals: [BigInt(6), BigInt(7), BigInt(8), BigInt(9), BigInt(10)], bonusball: BigInt(2) },
        { normals: [BigInt(6), BigInt(7), BigInt(8), BigInt(9), BigInt(10)], bonusball: BigInt(3) },
      ];
      const recipient = buyerOne.address;
      const referrers: Address[] = [];
      const referralSplitBps: bigint[] = [];
      const source = ethers.encodeBytes32String("test");
      
      const ticketIds = await jackpotBridgeManager.connect(owner.wallet).buyTickets.staticCall(
        tickets,
        recipient,
        referrers,
        referralSplitBps,
        source
      );

      await jackpotBridgeManager.connect(owner.wallet).buyTickets(
        tickets,
        recipient,
        referrers,
        referralSplitBps,
        source
      );

      await time.increase(jackpotSystem.deploymentParams.drawingDurationInSeconds + BigInt(1));
      const drawingState = await jackpot.getDrawingState(1);
      await jackpot.connect(owner.wallet).runJackpot(
        { value: jackpotSystem.deploymentParams.entropyFee + ((jackpotSystem.deploymentParams.entropyBaseGasLimit + jackpotSystem.deploymentParams.entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7)) }
      );
      await entropyProvider.connect(owner.wallet).randomnessCallback([[BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], [BigInt(2)]]);

      const rawUserWinnings = (await payoutCalculator.getTierPayout(1, 1)) + (await payoutCalculator.getTierPayout(1, 10));
      expectedUserWinnings = rawUserWinnings * (PRECISE_UNIT - jackpotSystem.deploymentParams.referralWinShare) / PRECISE_UNIT;
      subjectUserTicketIds = [...ticketIds]; // Create a mutable copy
      subjectBridgeDetails = {
        approveTo: await mockDepository.getAddress(),
        to: await mockDepository.getAddress(),
        data: mockDepository.interface.encodeFunctionData("depositErc20", [
          await jackpotBridgeManager.getAddress(),
          await usdcMock.getAddress(),
          expectedUserWinnings,
          ethers.encodeBytes32String("test")
        ])
      };

      subjectSignature = await generateClaimWinningsSignature(
        await jackpotBridgeManager.getAddress(),
        subjectUserTicketIds,
        subjectBridgeDetails,
        buyerOne.wallet
      );
    });

    async function subject() {
      return await jackpotBridgeManager.connect(owner.wallet).claimWinnings(
        subjectUserTicketIds,
        subjectBridgeDetails,
        subjectSignature
      );
    }

    it("should transfer tokens from the jackpot contract to the depository contract", async () => {
      const preJackpotBalance = await usdcMock.balanceOf(await jackpot.getAddress());
      const preDepositoryBalance = await usdcMock.balanceOf(await mockDepository.getAddress());

      await subject();

      const postJackpotBalance = await usdcMock.balanceOf(await jackpot.getAddress());
      const postDepositoryBalance = await usdcMock.balanceOf(await mockDepository.getAddress());
      expect(postJackpotBalance).to.eq(preJackpotBalance - expectedUserWinnings);
      expect(postDepositoryBalance).to.eq(preDepositoryBalance + expectedUserWinnings);
    });

    it("should emit the correct WinningsClaimed event", async () => {
      await expect(subject()).to.emit(jackpotBridgeManager, "WinningsClaimed").withArgs(
        buyerOne.address,
        await mockDepository.getAddress(),
        subjectUserTicketIds,
        expectedUserWinnings
      );
    });

    it("should emit the correct FundsBridged event", async () => {
      await expect(subject()).to.emit(jackpotBridgeManager, "FundsBridged").withArgs(
        await mockDepository.getAddress(),
        expectedUserWinnings
      );
    });

    describe("when the the amount is bridged via a direct xfer to a solver", async () => {
      beforeEach(async () => {
        subjectBridgeDetails.to = await usdcMock.getAddress();
        subjectBridgeDetails.approveTo = ADDRESS_ZERO;
        subjectBridgeDetails.data = usdcMock.interface.encodeFunctionData("transfer", [
          solver.address,
          expectedUserWinnings
        ]);

        subjectSignature = await generateClaimWinningsSignature(
          await jackpotBridgeManager.getAddress(),
          subjectUserTicketIds,
          subjectBridgeDetails,
          buyerOne.wallet
        );
      });

      it("should transfer tokens from the jackpot contract to the depository contract", async () => {
        const preJackpotBalance = await usdcMock.balanceOf(await jackpot.getAddress());
        const preSolverBalance = await usdcMock.balanceOf(solver.address);
  
        await subject();
  
        const postJackpotBalance = await usdcMock.balanceOf(await jackpot.getAddress());
        const postSolverBalance = await usdcMock.balanceOf(solver.address);
        expect(postJackpotBalance).to.eq(preJackpotBalance - expectedUserWinnings);
        expect(postSolverBalance).to.eq(preSolverBalance + expectedUserWinnings);
      });
  
      it("should emit the correct WinningsClaimed event", async () => {
        await expect(subject()).to.emit(jackpotBridgeManager, "WinningsClaimed").withArgs(
          buyerOne.address,
          await usdcMock.getAddress(),
          subjectUserTicketIds,
          expectedUserWinnings
        );
      });
  
      it("should emit the correct FundsBridged event", async () => {
        await expect(subject()).to.emit(jackpotBridgeManager, "FundsBridged").withArgs(
          await usdcMock.getAddress(),
          expectedUserWinnings
        );
      });
    });

    describe("when the bridging transfer fails", async () => {
      beforeEach(async () => {
        subjectBridgeDetails.to = await usdcMock.getAddress();

        subjectSignature = await generateClaimWinningsSignature(
          await jackpotBridgeManager.getAddress(),
          subjectUserTicketIds,
          subjectBridgeDetails,
          buyerOne.wallet
        );
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotBridgeManager, "BridgeFundsFailed");
      });
    });

    describe("when the full amount of winnings is not bridged", async () => {
      beforeEach(async () => {
        subjectBridgeDetails.data = mockDepository.interface.encodeFunctionData("depositErc20", [
          await jackpotBridgeManager.getAddress(),
          await usdcMock.getAddress(),
          expectedUserWinnings - usdc(1),
          ethers.encodeBytes32String("test")
        ]);

        subjectSignature = await generateClaimWinningsSignature(
          await jackpotBridgeManager.getAddress(),
          subjectUserTicketIds,
          subjectBridgeDetails,
          buyerOne.wallet
        );
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotBridgeManager, "NotAllFundsBridged");
      });
    });

    describe("when the claimed amount is zero", async () => {
      beforeEach(async () => {
        subjectBridgeDetails.data = mockDepository.interface.encodeFunctionData("depositErc20", [
          await jackpotBridgeManager.getAddress(),
          await usdcMock.getAddress(),
          expectedUserWinnings - usdc(1),
          ethers.encodeBytes32String("test")
        ]);

        subjectUserTicketIds = [subjectUserTicketIds[2]];
        subjectSignature = await generateClaimWinningsSignature(
          await jackpotBridgeManager.getAddress(),
          subjectUserTicketIds,
          subjectBridgeDetails,
          buyerOne.wallet
        );
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotBridgeManager, "InvalidClaimedAmount");
      });
    });

    describe("when the user does not own the tickets", async () => {
      beforeEach(async () => {
        subjectSignature = await generateClaimWinningsSignature(
          await jackpotBridgeManager.getAddress(),
          subjectUserTicketIds,
          subjectBridgeDetails,
          buyerTwo.wallet
        );
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotBridgeManager, "NotTicketOwner");
      });
    });

    describe("when an empty tickets array is provided", async () => {
      beforeEach(async () => {
        subjectUserTicketIds = [];
        subjectSignature = await generateClaimWinningsSignature(
          await jackpotBridgeManager.getAddress(),
          subjectUserTicketIds,
          subjectBridgeDetails,
          buyerTwo.wallet
        );
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotBridgeManager, "NoTicketsToClaim");
      });
    });

    describe("when the reentrancy protection is violated", async () => {
      beforeEach(async () => {
        await usdcMock.setCallbackTarget(await jackpotBridgeManager.getAddress());
        const callbackData = jackpotBridgeManager.interface.encodeFunctionData(
          "claimWinnings",
          [
            subjectUserTicketIds,
            subjectBridgeDetails,
            subjectSignature
          ]
        );
        await usdcMock.setCallbackData(callbackData);
        await usdcMock.enableCallback();
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotBridgeManager, "ReentrancyGuardReentrantCall");
      });
    });
  });

  describe("#claimTickets", async () => {
    let subjectTicketIds: bigint[];
    let subjectRecipient: Address;
    let subjectSignature: string;

    beforeEach(async () => {
      await usdcMock.connect(owner.wallet).approve(jackpotBridgeManager.getAddress(), usdc(5));
      
      const tickets: Ticket[] = [
        { normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], bonusball: BigInt(1) },
        { normals: [BigInt(6), BigInt(7), BigInt(8), BigInt(9), BigInt(10)], bonusball: BigInt(2) },
      ];
      const recipient = buyerOne.address;
      const referrers: Address[] = [referrerOne.address, referrerTwo.address, referrerThree.address];
      const referralSplitBps: bigint[] = [ether(.3333), ether(.3333), ether(.3334)];
      const source = ethers.encodeBytes32String("test");
      
      const ticketIds = await jackpotBridgeManager.connect(owner.wallet).buyTickets.staticCall(
        tickets,
        recipient,
        referrers,
        referralSplitBps,
        source
      );

      await jackpotBridgeManager.connect(owner.wallet).buyTickets(
        tickets,
        recipient,
        referrers,
        referralSplitBps,
        source
      );

      subjectTicketIds = [...ticketIds];
      subjectRecipient = buyerTwo.address;

      subjectSignature = await generateClaimTicketSignature(
        await jackpotBridgeManager.getAddress(),
        subjectTicketIds,
        subjectRecipient,
        buyerOne.wallet
      );
    });

    async function subject() {
      return await jackpotBridgeManager.connect(owner.wallet).claimTickets(
        subjectTicketIds,
        subjectRecipient,
        subjectSignature
      );
    }

    it("should transfer the ticket to the recipient", async () => {
      await subject();

      expect(await jackpotNFT.ownerOf(subjectTicketIds[0])).to.eq(subjectRecipient);
      expect(await jackpotNFT.ownerOf(subjectTicketIds[1])).to.eq(subjectRecipient);
    });

    describe("when the recipient is the bridge manager", async () => {
      beforeEach(async () => {
        subjectRecipient = await jackpotBridgeManager.getAddress();
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotBridgeManager, "InvalidRecipient");
      });
    });

    describe("when the recipient is the zero address", async () => {
      beforeEach(async () => {
        subjectRecipient = ADDRESS_ZERO;
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotBridgeManager, "ZeroAddress");
      });
    });
  });

  describe("#getUserTickets", () => {
    let subjectUser: Address;
    let subjectDrawingId: bigint;

    beforeEach(async () => {
      subjectUser = buyerOne.address;
      subjectDrawingId = 1n;
    });

    async function subject(): Promise<bigint[]> {
      return await jackpotBridgeManager.getUserTickets(subjectUser, subjectDrawingId);
    }

    describe("when user has no tickets", () => {
      it("should return empty array", async () => {
        const userTickets = await subject();
        expect(userTickets.length).to.equal(0);
      });
    });

    describe("when user has tickets they still own", () => {
      let expectedTicketIds: bigint[];

      beforeEach(async () => {
        await usdcMock.connect(owner.wallet).approve(jackpotBridgeManager.getAddress(), usdc(5));
        
        const tickets: Ticket[] = [
          { normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], bonusball: BigInt(1) },
          { normals: [BigInt(6), BigInt(7), BigInt(8), BigInt(9), BigInt(10)], bonusball: BigInt(2) },
        ];
        const recipient = buyerOne.address;
        const referrers: Address[] = [];
        const referralSplitBps: bigint[] = [];
        const source = ethers.encodeBytes32String("test");
        
        const ticketIds = await jackpotBridgeManager.connect(owner.wallet).buyTickets.staticCall(
          tickets,
          recipient,
          referrers,
          referralSplitBps,
          source
        );
        
        expectedTicketIds = [...ticketIds]; // Create mutable copy

        await jackpotBridgeManager.connect(owner.wallet).buyTickets(
          tickets,
          recipient,
          referrers,
          referralSplitBps,
          source
        );
      });

      it("should return all owned tickets for the drawing", async () => {
        const userTickets = await subject();
        expect(userTickets.length).to.equal(2);
        expect(userTickets[0]).to.equal(expectedTicketIds[0]);
        expect(userTickets[1]).to.equal(expectedTicketIds[1]);
      });

      it("should verify ownership mapping matches", async () => {
        const userTickets = await subject();
        for (const ticketId of userTickets) {
          if (ticketId !== 0n) { // Skip zero entries from transferred tickets
            const owner = await jackpotBridgeManager.ticketOwner(ticketId);
            expect(owner).to.equal(subjectUser);
          }
        }
      });
    });

    describe("when user has tickets that have been transferred away", () => {
      let originalTicketIds: bigint[];

      beforeEach(async () => {
        await usdcMock.connect(owner.wallet).approve(jackpotBridgeManager.getAddress(), usdc(5));
        
        const tickets: Ticket[] = [
          { normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], bonusball: BigInt(1) },
          { normals: [BigInt(6), BigInt(7), BigInt(8), BigInt(9), BigInt(10)], bonusball: BigInt(2) },
        ];
        const recipient = buyerOne.address;
        const referrers: Address[] = [];
        const referralSplitBps: bigint[] = [];
        const source = ethers.encodeBytes32String("test");
        
        const ticketIds = await jackpotBridgeManager.connect(owner.wallet).buyTickets.staticCall(
          tickets,
          recipient,
          referrers,
          referralSplitBps,
          source
        );
        
        originalTicketIds = [...ticketIds]; // Create mutable copy

        await jackpotBridgeManager.connect(owner.wallet).buyTickets(
          tickets,
          recipient,
          referrers,
          referralSplitBps,
          source
        );

        // Transfer all tickets away using claimTickets
        const signature = await generateClaimTicketSignature(
          await jackpotBridgeManager.getAddress(),
          originalTicketIds,
          buyerTwo.address,
          buyerOne.wallet
        );

        await jackpotBridgeManager.connect(owner.wallet).claimTickets(
          originalTicketIds,
          buyerTwo.address,
          signature
        );
      });

      it("should return array with zeros for transferred tickets", async () => {
        const userTickets = await subject();
        expect(userTickets.length).to.equal(2); // Array length stays same
        expect(userTickets[0]).to.equal(0n); // Ticket transferred, so zero
        expect(userTickets[1]).to.equal(0n); // Ticket transferred, so zero
      });

      it("should verify ticket ownership has been cleared", async () => {
        for (const ticketId of originalTicketIds) {
          const owner = await jackpotBridgeManager.ticketOwner(ticketId);
          expect(owner).to.equal(ethers.ZeroAddress); // Ownership cleared by claimTickets
        }
      });
    });

    describe("when user has mixed ownership (some transferred, some not)", () => {
      let originalTicketIds: bigint[];

      beforeEach(async () => {
        await usdcMock.connect(owner.wallet).approve(jackpotBridgeManager.getAddress(), usdc(15));
        
        const tickets: Ticket[] = [
          { normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], bonusball: BigInt(1) },
          { normals: [BigInt(6), BigInt(7), BigInt(8), BigInt(9), BigInt(10)], bonusball: BigInt(2) },
          { normals: [BigInt(11), BigInt(12), BigInt(13), BigInt(14), BigInt(15)], bonusball: BigInt(3) },
        ];
        const recipient = buyerOne.address;
        const referrers: Address[] = [];
        const referralSplitBps: bigint[] = [];
        const source = ethers.encodeBytes32String("test");
        
        const ticketIds = await jackpotBridgeManager.connect(owner.wallet).buyTickets.staticCall(
          tickets,
          recipient,
          referrers,
          referralSplitBps,
          source
        );
        
        originalTicketIds = [...ticketIds]; // Create mutable copy

        await jackpotBridgeManager.connect(owner.wallet).buyTickets(
          tickets,
          recipient,
          referrers,
          referralSplitBps,
          source
        );

        // Transfer only the middle ticket (index 1)
        const ticketsToTransfer = [originalTicketIds[1]];
        const signature = await generateClaimTicketSignature(
          await jackpotBridgeManager.getAddress(),
          ticketsToTransfer,
          buyerTwo.address,
          buyerOne.wallet
        );

        await jackpotBridgeManager.connect(owner.wallet).claimTickets(
          ticketsToTransfer,
          buyerTwo.address,
          signature
        );
      });

      it("should return mixed array with zeros for transferred tickets", async () => {
        const userTickets = await subject();
        expect(userTickets.length).to.equal(3);
        expect(userTickets[0]).to.equal(originalTicketIds[0]); // Still owned
        expect(userTickets[1]).to.equal(0n); // Transferred
        expect(userTickets[2]).to.equal(originalTicketIds[2]); // Still owned
      });

      it("should verify mixed ownership states", async () => {
        // First ticket - still owned
        const owner0 = await jackpotBridgeManager.ticketOwner(originalTicketIds[0]);
        expect(owner0).to.equal(subjectUser);
        
        // Second ticket - transferred
        const owner1 = await jackpotBridgeManager.ticketOwner(originalTicketIds[1]);
        expect(owner1).to.equal(ethers.ZeroAddress);
        
        // Third ticket - still owned
        const owner2 = await jackpotBridgeManager.ticketOwner(originalTicketIds[2]);
        expect(owner2).to.equal(subjectUser);
      });
    });

    describe("when user has tickets in multiple drawings", () => {
      let drawing1TicketIds: bigint[];
      let drawing2TicketIds: bigint[];

      beforeEach(async () => {
        await usdcMock.connect(owner.wallet).approve(jackpotBridgeManager.getAddress(), usdc(10));
        
        const tickets: Ticket[] = [
          { normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], bonusball: BigInt(1) },
          { normals: [BigInt(6), BigInt(7), BigInt(8), BigInt(9), BigInt(10)], bonusball: BigInt(2) },
        ];
        const recipient = buyerOne.address;
        const referrers: Address[] = [];
        const referralSplitBps: bigint[] = [];
        const source = ethers.encodeBytes32String("test");
        
        // Buy tickets for drawing 1
        const drawing1Tickets = await jackpotBridgeManager.connect(owner.wallet).buyTickets.staticCall(
          tickets,
          recipient,
          referrers,
          referralSplitBps,
          source
        );
        
        drawing1TicketIds = [...drawing1Tickets]; // Create mutable copy

        await jackpotBridgeManager.connect(owner.wallet).buyTickets(
          tickets,
          recipient,
          referrers,
          referralSplitBps,
          source
        );

        // Advance to next drawing
        await time.increase(jackpotSystem.deploymentParams.drawingDurationInSeconds + BigInt(1));
        const drawingState = await jackpot.getDrawingState(1);
        await jackpot.connect(owner.wallet).runJackpot(
          { value: jackpotSystem.deploymentParams.entropyFee + ((jackpotSystem.deploymentParams.entropyBaseGasLimit + jackpotSystem.deploymentParams.entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7)) }
        );
        await entropyProvider.connect(owner.wallet).randomnessCallback([[BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], [BigInt(1)]]);

        // Buy tickets for drawing 2
        const moreTickets: Ticket[] = [
          { normals: [BigInt(11), BigInt(12), BigInt(13), BigInt(14), BigInt(15)], bonusball: BigInt(3) },
        ];

        const drawing2Tickets = await jackpotBridgeManager.connect(owner.wallet).buyTickets.staticCall(
          moreTickets,
          recipient,
          referrers,
          referralSplitBps,
          source
        );
        
        drawing2TicketIds = [...drawing2Tickets]; // Create mutable copy

        await jackpotBridgeManager.connect(owner.wallet).buyTickets(
          moreTickets,
          recipient,
          referrers,
          referralSplitBps,
          source
        );
      });

      it("should return only tickets for drawing 1 when requested", async () => {
        subjectDrawingId = 1n;
        const userTickets = await subject();
        expect(userTickets.length).to.equal(2);
        expect(userTickets[0]).to.equal(drawing1TicketIds[0]);
        expect(userTickets[1]).to.equal(drawing1TicketIds[1]);
      });

      it("should return only tickets for drawing 2 when requested", async () => {
        subjectDrawingId = 2n;
        const userTickets = await subject();
        expect(userTickets.length).to.equal(1);
        expect(userTickets[0]).to.equal(drawing2TicketIds[0]);
      });

      it("should return empty array for drawing with no tickets", async () => {
        subjectDrawingId = 99n; // Non-existent drawing
        const userTickets = await subject();
        expect(userTickets.length).to.equal(0);
      });
    });

    describe("when querying different users", () => {
      let buyerOneTickets: bigint[];
      let buyerTwoTickets: bigint[];

      beforeEach(async () => {
        await usdcMock.connect(owner.wallet).approve(jackpotBridgeManager.getAddress(), usdc(10));
        
        const tickets: Ticket[] = [
          { normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], bonusball: BigInt(1) },
          { normals: [BigInt(6), BigInt(7), BigInt(8), BigInt(9), BigInt(10)], bonusball: BigInt(2) },
        ];
        const referrers: Address[] = [];
        const referralSplitBps: bigint[] = [];
        const source = ethers.encodeBytes32String("test");
        
        // Buy tickets for buyerOne
        const buyerOneTicketIds = await jackpotBridgeManager.connect(owner.wallet).buyTickets.staticCall(
          tickets,
          buyerOne.address,
          referrers,
          referralSplitBps,
          source
        );
        
        buyerOneTickets = [...buyerOneTicketIds]; // Create mutable copy

        await jackpotBridgeManager.connect(owner.wallet).buyTickets(
          tickets,
          buyerOne.address,
          referrers,
          referralSplitBps,
          source
        );

        // Buy different tickets for buyerTwo
        const moreTickets: Ticket[] = [
          { normals: [BigInt(11), BigInt(12), BigInt(13), BigInt(14), BigInt(15)], bonusball: BigInt(3) },
        ];

        const buyerTwoTicketIds = await jackpotBridgeManager.connect(owner.wallet).buyTickets.staticCall(
          moreTickets,
          buyerTwo.address,
          referrers,
          referralSplitBps,
          source
        );
        
        buyerTwoTickets = [...buyerTwoTicketIds]; // Create mutable copy

        await jackpotBridgeManager.connect(owner.wallet).buyTickets(
          moreTickets,
          buyerTwo.address,
          referrers,
          referralSplitBps,
          source
        );
      });

      it("should return correct tickets for buyerOne", async () => {
        subjectUser = buyerOne.address;
        const userTickets = await subject();
        expect(userTickets.length).to.equal(2);
        expect(userTickets[0]).to.equal(buyerOneTickets[0]);
        expect(userTickets[1]).to.equal(buyerOneTickets[1]);
      });

      it("should return correct tickets for buyerTwo", async () => {
        subjectUser = buyerTwo.address;
        const userTickets = await subject();
        expect(userTickets.length).to.equal(1);
        expect(userTickets[0]).to.equal(buyerTwoTickets[0]);
      });

      it("should return empty array for user with no tickets", async () => {
        subjectUser = referrerOne.address; // User who never bought tickets
        const userTickets = await subject();
        expect(userTickets.length).to.equal(0);
      });
    });
  });
});
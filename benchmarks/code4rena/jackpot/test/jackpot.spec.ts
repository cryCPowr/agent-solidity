import { ethers } from "hardhat";
import DeployHelper from "@utils/deploys";

import {
  getWaffleExpect,
  getAccounts
} from "@utils/test/index";
import { ether, usdc } from "@utils/common"
import { Account } from "@utils/test";

import {
  ETHRejectingContract,
  GuaranteedMinimumPayoutCalculator,
  Jackpot,
  JackpotLPManager,
  JackpotTicketNFT,
  ReentrantUSDCMock,
  ScaledEntropyProviderMock
} from "@utils/contracts";
import {
  Address,
  ComboCount,
  DrawingState,
  DrawingTierInfo,
  ExtendedTrackedTicket,
  LP,
  LPDrawingState,
  ReferralScheme,
  Ticket,
} from "@utils/types";
import {
  calculateLpPoolCap,
  calculateReferralSchemeId,
  calculatePackedTicket,
  calculateTicketId,
  calculateTotalDrawingPayout,
  calculateBonusballMax
} from "@utils/protocolUtils";
import { ADDRESS_ZERO,
  ONE_DAY_IN_SECONDS, PRECISE_UNIT, ZERO, ZERO_BYTES32 } from "@utils/constants";
import { takeSnapshot, SnapshotRestorer, time } from "@nomicfoundation/hardhat-toolbox/network-helpers";

const expect = getWaffleExpect();

describe("Jackpot", () => {
  let owner: Account;
  let user: Account;
  let lpOne: Account;
  let buyerOne: Account;
  let buyerTwo: Account;
  let buyerThree: Account;
  let referrerOne: Account;
  let referrerTwo: Account;
  let referrerThree: Account;

  let jackpot: Jackpot;
  let jackpotLPManager: JackpotLPManager;
  let jackpotNFT: JackpotTicketNFT;
  let payoutCalculator: GuaranteedMinimumPayoutCalculator;
  let usdcMock: ReentrantUSDCMock;
  let entropyProvider: ScaledEntropyProviderMock;
  let snapshot: SnapshotRestorer;

  const drawingDurationInSeconds: bigint = ONE_DAY_IN_SECONDS;
  const normalBallMax: bigint = BigInt(30);
  const bonusballMin: bigint = BigInt(5);
  const lpEdgeTarget: bigint = ether(0.3);
  const reserveRatio: bigint = ether(0.2);
  const referralFee: bigint = ether(0.065);
  const referralWinShare: bigint = ether(0.05);
  const protocolFee: bigint = ether(0.01);
  const protocolFeeThreshold: bigint = usdc(2);
  const ticketPrice: bigint = usdc(1);
  const maxReferrers: bigint = BigInt(5);
  const premiumTierWeights = [
    ether(0),
    ether(0.17),
    ether(0),
    ether(0.13),
    ether(0.12),
    ether(0.05),
    ether(0.05),
    ether(0.02),
    ether(0.02),
    ether(0.01),
    ether(0.04),
    ether(0.39),
  ];
  const minPayoutTiers = premiumTierWeights.map((value) => value > 0);
  const minimumPayout: bigint = usdc(1);
  const premiumTierMinAllocation: bigint = ether(.2);

  const entropyFee: bigint = ether(0.00005);
  const entropyBaseGasLimit: bigint = BigInt(1000000);
  const entropyVariableGasLimit: bigint = BigInt(250000);

  beforeEach(async () => {
    [
      owner,
      user,
      lpOne,
      buyerOne,
      buyerTwo,
      buyerThree,
      referrerOne,
      referrerTwo,
      referrerThree
    ] = await getAccounts();
    const deployer = new DeployHelper(owner.wallet);

    usdcMock = await deployer.deployReentrantUSDCMock(usdc(1000000000), "USDC", "USDC");
    await usdcMock.connect(owner.wallet).transfer(lpOne.address, usdc(100000000));
    await usdcMock.connect(owner.wallet).transfer(buyerOne.address, usdc(1000));
    await usdcMock.connect(owner.wallet).transfer(buyerTwo.address, usdc(1000));
    await usdcMock.connect(owner.wallet).transfer(buyerThree.address, usdc(1000));

    jackpot = await deployer.deployJackpot(
      drawingDurationInSeconds,
      normalBallMax,
      bonusballMin,
      lpEdgeTarget,
      reserveRatio,
      referralFee,
      referralWinShare,
      protocolFee,
      protocolFeeThreshold,
      ticketPrice,
      maxReferrers,
      entropyBaseGasLimit
    );

    jackpotNFT = await deployer.deployJackpotTicketNFT(await jackpot.getAddress());
    jackpotLPManager = await deployer.deployJackpotLPManager(await jackpot.getAddress());
    payoutCalculator = await deployer.deployGuaranteedMinimumPayoutCalculator(
      await jackpot.getAddress(),
      minimumPayout,
      premiumTierMinAllocation,
      minPayoutTiers,
      premiumTierWeights
    );

    entropyProvider = await deployer.deployScaledEntropyProviderMock(
      entropyFee,
      await jackpot.getAddress(),
      jackpot.interface.getFunction("scaledEntropyCallback").selector
    );
    
    snapshot = await takeSnapshot();
  });

  beforeEach(async () => {
    await snapshot.restore();
  });

  describe("#constructor", async () => {
    it("should set the correct state variables", async () => {
      const actualDrawingDurationInSeconds = await jackpot.drawingDurationInSeconds();
      const actualNormalBallRange = await jackpot.normalBallMax();
      const actualBonusballMin = await jackpot.bonusballMin();
      const actualLpEdgeTarget = await jackpot.lpEdgeTarget();
      const actualReserveRatio = await jackpot.reserveRatio();
      const actualReferralFeeBps = await jackpot.referralFee();
      const actualReferralWinShareBps = await jackpot.referralWinShare();
      const actualProtocolFeeBps = await jackpot.protocolFee();
      const actualProtocolFeeThreshold = await jackpot.protocolFeeThreshold();
      const actualProtocolFeeAddress = await jackpot.protocolFeeAddress();
      const actualTicketPrice = await jackpot.ticketPrice();
      const actualMaxReferrers = await jackpot.maxReferrers();
      const actualEntropyBaseGasLimit = await jackpot.entropyBaseGasLimit();
      const actualEntropyVariableGasLimit = await jackpot.entropyVariableGasLimit();

      expect(actualDrawingDurationInSeconds).to.eq(drawingDurationInSeconds);
      expect(actualNormalBallRange).to.eq(normalBallMax);
      expect(actualBonusballMin).to.eq(bonusballMin);
      expect(actualLpEdgeTarget).to.eq(lpEdgeTarget);
      expect(actualReserveRatio).to.eq(reserveRatio);
      expect(actualReferralFeeBps).to.eq(referralFee);
      expect(actualReferralWinShareBps).to.eq(referralWinShare);
      expect(actualProtocolFeeBps).to.eq(protocolFee);
      expect(actualProtocolFeeThreshold).to.eq(protocolFeeThreshold);
      expect(actualProtocolFeeAddress).to.eq(owner.address);
      expect(actualTicketPrice).to.eq(ticketPrice);
      expect(actualMaxReferrers).to.eq(maxReferrers);
      expect(actualEntropyBaseGasLimit).to.eq(entropyBaseGasLimit);
      expect(actualEntropyVariableGasLimit).to.eq(BigInt(250000));
    });
  });

  describe("#initialize", async () => {
    let subjectUsdc: Address;
    let subjectJackpotLPManager: Address;
    let subjectJackpotNFT: Address;
    let subjectEntropy: Address;
    let subjectPayoutCalculator: Address;
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectUsdc = await usdcMock.getAddress();
      subjectJackpotLPManager = await jackpotLPManager.getAddress();
      subjectJackpotNFT = await jackpotNFT.getAddress();
      subjectEntropy = await entropyProvider.getAddress();
      subjectPayoutCalculator = await payoutCalculator.getAddress();
      subjectCaller = owner;
    });

    async function subject(): Promise<any> {
      return await jackpot.connect(subjectCaller.wallet).initialize(
        subjectUsdc,
        subjectJackpotLPManager,
        subjectJackpotNFT,
        subjectEntropy,
        subjectPayoutCalculator
      );
    }

    it("should set the correct state variables and initialize the contract", async () => {
      const preInitialized = await jackpot.initialized();
      expect(preInitialized).to.be.false;

      await subject();

      const actualUsdc = await jackpot.usdc();
      const actualJackpotNFT = await jackpot.jackpotNFT();
      const actualEntropy = await jackpot.entropy();
      const actualInitialized = await jackpot.initialized();
      const actualPayoutCalculator = await jackpot.payoutCalculator();

      expect(actualUsdc).to.eq(subjectUsdc);
      expect(actualJackpotNFT).to.eq(subjectJackpotNFT);
      expect(actualEntropy).to.eq(subjectEntropy);
      expect(actualInitialized).to.be.true
      expect(actualPayoutCalculator).to.deep.equal(subjectPayoutCalculator);
    });

    describe("when the contract is already initialized", async () => {
      beforeEach(async () => {
        await subject();
      });

      it("should revert if the contract is already initialized", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpot, "ContractAlreadyInitialized");
      });
    });

    describe("when the jackpot LP manager is not set", async () => {
      beforeEach(async () => {
        subjectJackpotLPManager = ADDRESS_ZERO;
      });

      it("should revert if the jackpot LP manager is not set", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpot, "ZeroAddress");
      });
    });

    describe("when the jackpot NFT is not set", async () => {
      beforeEach(async () => {
        subjectJackpotNFT = ADDRESS_ZERO;
      });

      it("should revert if the jackpot NFT is not set", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpot, "ZeroAddress");
      });
    });

    describe("when the entropy provider is not set", async () => {
      beforeEach(async () => {
        subjectEntropy = ADDRESS_ZERO;
      });

      it("should revert if the entropy provider is not set", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpot, "ZeroAddress");
      });
    });

    describe("when the payout calculator is not set", async () => {
      beforeEach(async () => {
        subjectPayoutCalculator = ADDRESS_ZERO;
      });

      it("should revert if the payout calculator is not set", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpot, "ZeroAddress");
      });
    });

    describe("when the usdc is not set", async () => {
      beforeEach(async () => {
        subjectUsdc = ADDRESS_ZERO;
      });

      it("should revert if the usdc is not set", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpot, "ZeroAddress");
      });
    });

    describe("when the caller is not the owner", async () => {
      beforeEach(async () => {
        subjectCaller = user;
      });

      it("should revert if the caller is not the owner", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
      });
    });
  });

  describe("#initializeLPDeposits", async () => {
    let isInitialized: boolean = true;

    let subjectGovernancePoolCap: bigint;
    let subjectCaller: Account;

    beforeEach(async () => {
      if (isInitialized) {
        await jackpot.connect(owner.wallet).initialize(
          (await usdcMock.getAddress()),
          await jackpotLPManager.getAddress(),
          await jackpotNFT.getAddress(),
          await entropyProvider.getAddress(),
          await payoutCalculator.getAddress()
        );
      }
      subjectGovernancePoolCap = usdc(100000000);
      subjectCaller = owner;
    });

    async function subject(): Promise<any> {
      return await jackpot.connect(subjectCaller.wallet).initializeLPDeposits(subjectGovernancePoolCap);
    }

    it("should set the correct state variables and initialize the lp pool", async () => {
      await subject();

      const actualLpPoolCap = await jackpotLPManager.lpPoolCap();
      const actualDrawingAccumulator = await jackpotLPManager.getDrawingAccumulator(0);
      const actualGovernancePoolCap = await jackpot.governancePoolCap();

      const expectedLpPoolCap = calculateLpPoolCap(normalBallMax, ticketPrice, lpEdgeTarget, reserveRatio);

      expect(actualLpPoolCap).to.eq(expectedLpPoolCap);
      expect(actualDrawingAccumulator).to.eq(PRECISE_UNIT);
      expect(actualGovernancePoolCap).to.eq(subjectGovernancePoolCap);
    });

    describe("when the contract is not initialized", async () => {
      before(async () => {
        isInitialized = false;
      });

      after(async () => {
        isInitialized = true;
      });

      it("should revert if the contract is not initialized", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpot, "ContractNotInitialized");
      });
    });

    describe("when the lp deposits are already initialized", async () => {

      beforeEach(async () => {
        await subject();
      });

      it("should revert if the lp deposits are already initialized", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpot, "LPDepositsAlreadyInitialized");
      });
    });

    describe("when the governancePoolCap is zero", async () => {
      beforeEach(async () => {
        subjectGovernancePoolCap = 0n;
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidGovernancePoolCap");
      });
    });

    describe("when the caller is not the owner", async () => {
      beforeEach(async () => {
        subjectCaller = user;
      });

      it("should revert if the caller is not the owner", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
      });
    });
  });

  context("when the contract has been initialized", async () => {
    beforeEach(async () => {
      await jackpot.connect(owner.wallet).initialize(
        (await usdcMock.getAddress()),
        await jackpotLPManager.getAddress(),
        await jackpotNFT.getAddress(),
        await entropyProvider.getAddress(),
        await payoutCalculator.getAddress()
      );
    });

    describe("#lpDeposit", async () => {
      let subjectAmountToDeposit: bigint;
      let subjectCaller: Account;

      beforeEach(async () => {
        await jackpot.connect(owner.wallet).initializeLPDeposits(usdc(100000000));
        await usdcMock.connect(lpOne.wallet).approve(jackpot.getAddress(), usdc(1000000));
        subjectAmountToDeposit = usdc(1000000);
        subjectCaller = lpOne;
      });

      async function subject(): Promise<any> {
        return await jackpot.connect(subjectCaller.wallet).lpDeposit(subjectAmountToDeposit);
      }

      it("should correctly update the pendingDeposits for the current drawing", async () => {
        await subject();

        const actualDrawingState: LPDrawingState = await jackpotLPManager.getLPDrawingState(0);
        expect(actualDrawingState.pendingDeposits).to.eq(subjectAmountToDeposit);
      });

      it("should correctly update the LP's LastDeposit state", async () => {
        await subject();

        const actualLpState: LP = await jackpotLPManager.getLpInfo(lpOne.address);
        expect(actualLpState.lastDeposit.amount).to.eq(subjectAmountToDeposit);
        expect(actualLpState.lastDeposit.drawingId).to.eq(0);
        expect(actualLpState.consolidatedShares).to.eq(0);
        expect(actualLpState.pendingWithdrawal.amountInShares).to.eq(0);
        expect(actualLpState.pendingWithdrawal.drawingId).to.eq(0);
        expect(actualLpState.claimableWithdrawals).to.eq(0);
      });

      it("should emit the LpDeposited event", async () => {
        await expect(subject()).to.emit(jackpotLPManager, "LpDeposited").withArgs(lpOne.address, 0, subjectAmountToDeposit, subjectAmountToDeposit);
      });

      describe("when the LP deposits again", async () => {
        beforeEach(async () => {
          await usdcMock.connect(lpOne.wallet).approve(jackpot.getAddress(), usdc(1000000));
          await subject();

          await usdcMock.connect(lpOne.wallet).approve(jackpot.getAddress(), usdc(1000000));
        });

        it("should correctly update the pendingDeposits for the current drawing", async () => {
          await subject();

          const actualDrawingState: LPDrawingState = await jackpotLPManager.getLPDrawingState(0);
          expect(actualDrawingState.pendingDeposits).to.eq(subjectAmountToDeposit * BigInt(2));
        });

        it("should correctly update the LP's LastDeposit state", async () => {
          await subject();

          const actualLpState: LP = await jackpotLPManager.getLpInfo(lpOne.address);
          expect(actualLpState.lastDeposit.amount).to.eq(subjectAmountToDeposit * BigInt(2));
          expect(actualLpState.lastDeposit.drawingId).to.eq(0);
        });

        it("should emit the LpDeposited event", async () => {
          await expect(subject()).to.emit(jackpotLPManager, "LpDeposited").withArgs(lpOne.address, 0, subjectAmountToDeposit, subjectAmountToDeposit * BigInt(2));
        });
      });

      describe("when the LP has a pending deposit from a previous drawing", async () => {
        beforeEach(async () => {
          await subject();

          await jackpot.connect(owner.wallet).initializeJackpot(BigInt(await time.latest()) + ONE_DAY_IN_SECONDS);

          await time.increase(drawingDurationInSeconds);

          await usdcMock.connect(lpOne.wallet).approve(jackpot.getAddress(), usdc(1000000));
        });

        it("should correctly update the LP's LastDeposit and consolidatedShares state", async () => {
          await subject();

          const lpState: LP = await jackpotLPManager.getLpInfo(lpOne.address);

          expect(lpState.lastDeposit.amount).to.eq(subjectAmountToDeposit);
          expect(lpState.lastDeposit.drawingId).to.eq(1);
          expect(lpState.consolidatedShares).to.eq(usdc(1000000));
        });

        it("should correctly update the pendingDeposits for the current drawing", async () => {
          await subject();

          const actualDrawingState: LPDrawingState = await jackpotLPManager.getLPDrawingState(0);
          expect(actualDrawingState.pendingDeposits).to.eq(subjectAmountToDeposit);
        });

        it("should emit the LpDeposited event", async () => {
          await expect(subject()).to.emit(jackpotLPManager, "LpDeposited").withArgs(lpOne.address, 1, subjectAmountToDeposit, subjectAmountToDeposit);
        });
      });

      describe("When the LP deposit amount is zero", async () => {
        beforeEach(async () => {
          subjectAmountToDeposit = usdc(0);
        });

        it("should revert", async () => {
          await expect(subject()).to.be.revertedWithCustomError(jackpot, "DepositAmountZero");
        });
      });

      describe("When the LP deposit amount exceeds the LP pool cap", async () => {
        beforeEach(async () => {
          await usdcMock.connect(lpOne.wallet).approve(jackpot.getAddress(), usdc(100000000));
          subjectAmountToDeposit = usdc(100000000);
        });
        
        it("should revert", async () => {
          await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "ExceedsPoolCap");
        });
      });

      describe("When the jackpot is locked", async () => {
        beforeEach(async () => {
          await jackpot.connect(owner.wallet).lockJackpot();
        });

        it("should revert", async () => {
          await expect(subject()).to.be.revertedWithCustomError(jackpot, "JackpotLocked");
        });
      });

      describe("when emergency mode is enabled", async () => {
        beforeEach(async () => {
          await jackpot.connect(owner.wallet).enableEmergencyMode();
        });

        it("should revert", async () => {
          await expect(subject()).to.be.revertedWithCustomError(jackpot, "EmergencyEnabled");
        });
      });

      describe("when the reentrancy protection is violated", async () => {
        beforeEach(async () => {
          await usdcMock.setCallbackTarget(await jackpot.getAddress());
          const callbackData = jackpot.interface.encodeFunctionData(
            "lpDeposit",
            [subjectAmountToDeposit]
          );
          await usdcMock.setCallbackData(callbackData)
          await usdcMock.enableCallback();
        });

        it("should revert", async () => {
          await expect(subject()).to.be.revertedWithCustomError(jackpot, "ReentrancyGuardReentrantCall");
        });
      });
    });

    describe("#initializeJackpot", async () => {
      let isLPInitialized: boolean = true;
      let isLPDeposited: boolean = true;

      let subjectInitialDrawingTime: bigint;
      let subjectCaller: Account;

      beforeEach(async () => {
        if (isLPInitialized) {
          await jackpot.connect(owner.wallet).initializeLPDeposits(usdc(100000000));
        }

        if (isLPDeposited && isLPInitialized) {
          await usdcMock.connect(lpOne.wallet).approve(jackpot.getAddress(), usdc(2000000));
          await jackpot.connect(lpOne.wallet).lpDeposit(usdc(2000000));
        }

        subjectInitialDrawingTime = BigInt(await time.latest()) + BigInt(drawingDurationInSeconds);
        subjectCaller = owner;
      });

      async function subject(): Promise<any> {
        return await jackpot.connect(subjectCaller.wallet).initializeJackpot(subjectInitialDrawingTime);
      }

      it("should set the correct state variables and initialize the jackpot", async () => {
        await subject();

        const actualAllowTicketPurchases = await jackpot.allowTicketPurchases();
        const actualCurrentDrawingId = await jackpot.currentDrawingId();

        expect(actualAllowTicketPurchases).to.be.true;
        expect(actualCurrentDrawingId).to.eq(1);
      });

      it("should correctly update the DrawingState for the first drawing", async () => {
        const currentLpDrawingState: LPDrawingState = await jackpotLPManager.getLPDrawingState(0);

        await subject();

        const actualDrawingState: DrawingState = await jackpot.getDrawingState(1);
        const expectedPrizePool = currentLpDrawingState.pendingDeposits*(PRECISE_UNIT-reserveRatio)/PRECISE_UNIT;
        const expectedBonusballMax = calculateBonusballMax(expectedPrizePool, normalBallMax, ticketPrice, lpEdgeTarget, bonusballMin);

        expect(actualDrawingState.prizePool).to.be.equal(expectedPrizePool);
        expect(actualDrawingState.drawingTime).to.be.equal(subjectInitialDrawingTime);
        expect(actualDrawingState.jackpotLock).to.be.false;
        expect(actualDrawingState.ballMax).to.be.equal(normalBallMax);
        expect(actualDrawingState.bonusballMax).to.be.equal(expectedBonusballMax);
        expect(actualDrawingState.globalTicketsBought).to.be.equal(0);
        expect(actualDrawingState.lpEarnings).to.be.equal(0);
        expect(actualDrawingState.winningTicket).to.be.equal(BigInt(0));
      });

      it("should correctly update the LPDrawingState for the first drawing", async () => {        
        const currentDrawingState: LPDrawingState = await jackpotLPManager.getLPDrawingState(0);

        await subject();

        const actualDrawingState: LPDrawingState = await jackpotLPManager.getLPDrawingState(1);
        const expectedLpPoolTotal = currentDrawingState.pendingDeposits;

        expect(actualDrawingState.lpPoolTotal).to.be.equal(expectedLpPoolTotal);
        expect(actualDrawingState.pendingDeposits).to.be.equal(0);
        expect(actualDrawingState.pendingWithdrawals).to.be.equal(0);
      });

      it("should set the correct tierInfo for first drawing", async () => {
        await subject();

        const actualTierInfo: DrawingTierInfo = await payoutCalculator.getDrawingTierInfo(BigInt(1));
        expect(actualTierInfo.minPayout).to.be.equal(minimumPayout);
        expect(actualTierInfo.minPayoutTiers).to.deep.equal(minPayoutTiers);
        expect(actualTierInfo.premiumTierWeights).to.deep.equal(premiumTierWeights);
      });

      describe("when the no deposits are made", async () => {
        before(async () => {
          isLPDeposited = false;
        });

        after(async () => {
          isLPDeposited = true;
        });

        it("should revert if the lp deposits are not initialized", async () => {
          await expect(subject()).to.be.revertedWithCustomError(jackpot, "NoLPDeposits");
        });
      });

      describe("when the lp deposits are not initialized", async () => {
        before(async () => {
          isLPInitialized = false;
        });

        after(async () => {
          isLPInitialized = true;
        });

        it("should revert if the lp deposits are not initialized", async () => {
          await expect(subject()).to.be.revertedWithCustomError(jackpot, "LPDepositsNotInitialized");
        });
      });

      describe("when the jackpot is already begun", async () => {
        beforeEach(async () => {
          await subject();
        });

        it("should revert if the jackpot is already begun", async () => {
          await expect(subject()).to.be.revertedWithCustomError(jackpot, "JackpotAlreadyInitialized");
        });
      });

      describe("when the caller is not the owner", async () => {
        beforeEach(async () => {
          subjectCaller = user;
        });
  
        it("should revert if the caller is not the owner", async () => {
          await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
        });
      });
    });

    context("when jackpot has been initialized", async () => {
      beforeEach(async () => {
        await jackpot.connect(owner.wallet).initializeLPDeposits(usdc(100000000));
        await usdcMock.connect(lpOne.wallet).approve(jackpot.getAddress(), usdc(2000000));
        await jackpot.connect(lpOne.wallet).lpDeposit(usdc(2000000));
        await jackpot.connect(owner.wallet).initializeJackpot(BigInt(await time.latest()) + ONE_DAY_IN_SECONDS);
      });

      describe("#buyTickets", async () => {
        let subjectTickets: Ticket[];
        let subjectRecipient: Address;
        let subjectReferrers: Address[];
        let subjectReferralSplitBps: bigint[];
        let subjectSource: string;
        let subjectCaller: Account;
  
        beforeEach(async () => {
          subjectTickets = [
            {
              normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
              bonusball: BigInt(1)
            } as Ticket,
            {
              normals: [BigInt(2), BigInt(4), BigInt(6), BigInt(7), BigInt(11)],
              bonusball: BigInt(3)
            } as Ticket,
          ];
  
          await usdcMock.connect(buyerOne.wallet).approve(jackpot.getAddress(), usdc(10));
  
          subjectRecipient = buyerOne.address;
          subjectReferrers = [referrerOne.address, referrerTwo.address, referrerThree.address];
          subjectReferralSplitBps = [ether(.3333), ether(.3333), ether(.3334)];
          subjectSource = ethers.encodeBytes32String("test");
          subjectCaller = buyerOne;
        });
  
        async function subject(): Promise<any> {
          return await jackpot.connect(subjectCaller.wallet).buyTickets(
            subjectTickets,
            subjectRecipient,
            subjectReferrers,
            subjectReferralSplitBps,
            subjectSource)
          ;
        }
  
        async function subjectStaticCall(): Promise<any> {
          return jackpot.connect(subjectCaller.wallet).buyTickets.staticCall(
            subjectTickets,
            subjectRecipient,
            subjectReferrers,
            subjectReferralSplitBps,
            subjectSource)
          ;
        }
  
        it("should correctly update the DrawingState for the current drawing", async () => {
          await subject();
  
          const actualDrawingState: DrawingState = await jackpot.getDrawingState(1);
  
          expect(actualDrawingState.globalTicketsBought).to.eq(BigInt(2));
          expect(actualDrawingState.lpEarnings).to.eq(
            BigInt(subjectTickets.length) * ticketPrice * (PRECISE_UNIT - referralFee) / PRECISE_UNIT
          );
        });
  
        it("should correctly transfer the USDC from the buyer to the contract", async () => {
          const preBuyerBalance = await usdcMock.balanceOf(buyerOne.address);
          const preContractBalance = await usdcMock.balanceOf(jackpot.getAddress());
  
          await subject();
  
          const postBuyerBalance = await usdcMock.balanceOf(buyerOne.address);
          const postContractBalance = await usdcMock.balanceOf(jackpot.getAddress());
  
          expect(postBuyerBalance).to.eq(preBuyerBalance - BigInt(subjectTickets.length) * ticketPrice);
          expect(postContractBalance).to.eq(preContractBalance + BigInt(subjectTickets.length) * ticketPrice);
        });
  
        it("should return the correct ticket ids", async () => {
          const ticketIds = await subjectStaticCall();
  
          const expectedTicketIdOne = calculateTicketId(1, 1, calculatePackedTicket(subjectTickets[0], BigInt(normalBallMax)));
          const expectedTicketIdTwo = calculateTicketId(1, 2, calculatePackedTicket(subjectTickets[1], BigInt(normalBallMax)));
  
          expect(ticketIds).to.deep.equal([expectedTicketIdOne, expectedTicketIdTwo]);
        });
  
        it("should correctly update the UserTickets for the current drawing", async () => {
          await subject();
  
          const packedUserTickets: ExtendedTrackedTicket[] = await jackpotNFT.getUserTickets(buyerOne.address, 1);

          expect(packedUserTickets[0].ticket.packedTicket).to.equal(calculatePackedTicket(subjectTickets[0], BigInt(normalBallMax)));
          expect(packedUserTickets[1].ticket.packedTicket).to.equal(calculatePackedTicket(subjectTickets[1], BigInt(normalBallMax)));
          expect(packedUserTickets[0].normals).to.deep.equal(subjectTickets[0].normals);
          expect(packedUserTickets[1].normals).to.deep.equal(subjectTickets[1].normals);
          expect(packedUserTickets[0].bonusball).to.equal(subjectTickets[0].bonusball);
          expect(packedUserTickets[1].bonusball).to.equal(subjectTickets[1].bonusball);
        });
  
        it("should correctly update ERC721 state", async () => {
          await subject();
  
          const ticketOneOwner = await jackpotNFT.ownerOf(calculateTicketId(1, 1, calculatePackedTicket(subjectTickets[0], BigInt(normalBallMax))));
          const ticketTwoOwner = await jackpotNFT.ownerOf(calculateTicketId(1, 2, calculatePackedTicket(subjectTickets[1], BigInt(normalBallMax))));
          const buyerBalance = await jackpotNFT.balanceOf(buyerOne.address);
  
          expect(buyerBalance).to.eq(BigInt(2));
          expect(ticketOneOwner).to.eq(buyerOne.address);
          expect(ticketTwoOwner).to.eq(buyerOne.address);
        });
  
        it("should correctly update the DrawingEntries for the current drawing", async () => {
          await subject();
  
          const areTicketsBought = await jackpot.checkIfTicketsBought(1, subjectTickets);
  
          expect(areTicketsBought).to.deep.equal([true, true]);
        });
  
        it("should correctly update the ticket mapping", async () => {
          await subject();
  
          const ticketOne = await jackpotNFT.tickets(calculateTicketId(1, 1, calculatePackedTicket(subjectTickets[0], BigInt(normalBallMax))));
          const ticketTwo = await jackpotNFT.tickets(calculateTicketId(1, 2, calculatePackedTicket(subjectTickets[1], BigInt(normalBallMax))));
  
          expect(ticketOne.drawingId).to.eq(1);
          expect(ticketOne.packedTicket).to.eq(calculatePackedTicket(subjectTickets[0], BigInt(normalBallMax)));
          expect(ticketOne.referralScheme).to.eq(calculateReferralSchemeId(subjectReferrers, subjectReferralSplitBps));
  
          expect(ticketTwo.drawingId).to.eq(1);
          expect(ticketTwo.packedTicket).to.eq(calculatePackedTicket(subjectTickets[1], BigInt(normalBallMax)));
        });
  
        it("should correctly update the state for referrers and referralSchemes", async () => {
          await subject();
  
          const referrerOneBalance = await jackpot.referralFees(referrerOne.address);
          const referrerTwoBalance = await jackpot.referralFees(referrerTwo.address);
          const referrerThreeBalance = await jackpot.referralFees(referrerThree.address);
  
          const referralSchemeId = calculateReferralSchemeId(subjectReferrers, subjectReferralSplitBps);
          const referralScheme: ReferralScheme = await jackpot.getReferralScheme(referralSchemeId);
  
          const expectedReferralFee = BigInt(subjectTickets.length) * ticketPrice * referralFee / PRECISE_UNIT;
          expect(referrerOneBalance).to.eq(expectedReferralFee * ether(.3333) / PRECISE_UNIT);
          expect(referrerTwoBalance).to.eq(expectedReferralFee * ether(.3333) / PRECISE_UNIT);
          expect(referrerThreeBalance).to.eq(expectedReferralFee * ether(.3334) / PRECISE_UNIT);
  
          expect(referralScheme.referrers).to.deep.equal(subjectReferrers);
          expect(referralScheme.referralSplit).to.deep.equal(subjectReferralSplitBps);
        });
  
        it("should emit the correct TicketPurchased event", async () => {
          const packedTicketOne = calculatePackedTicket(subjectTickets[0], BigInt(normalBallMax));
          await expect(subject()).to.emit(jackpot, "TicketPurchased").withArgs(
            subjectRecipient,
            BigInt(1),
            subjectSource,
            calculateTicketId(1, 1, packedTicketOne),
            subjectTickets[0].normals,
            subjectTickets[0].bonusball,
            calculateReferralSchemeId(subjectReferrers, subjectReferralSplitBps)
          );
        });
  
        it("should emit the correct TicketOrderProcessed event", async () => {
          await subject();

          await expect(subject()).to.emit(jackpot, "TicketOrderProcessed").withArgs(
            buyerOne.address,
            subjectRecipient,
            1,
            subjectTickets.length,
            BigInt(subjectTickets.length) * ticketPrice * (PRECISE_UNIT - referralFee) / PRECISE_UNIT,
            BigInt(subjectTickets.length) * ticketPrice * referralFee / PRECISE_UNIT
          );
        });

        it("should emit the correct ReferralFeeCollected events", async () => {
          const expectedReferralFee = BigInt(subjectTickets.length) * ticketPrice * referralFee / PRECISE_UNIT;
          const expectedReferrerFeeOne = expectedReferralFee * ether(.3333) / PRECISE_UNIT;
          const expectedReferrerFeeTwo = expectedReferralFee * ether(.3333) / PRECISE_UNIT;
          const expectedReferrerFeeThree = expectedReferralFee * ether(.3334) / PRECISE_UNIT;

          await expect(subject())
            .to.emit(jackpot, "ReferralFeeCollected").withArgs(referrerOne.address, expectedReferrerFeeOne)
            .and.to.emit(jackpot, "ReferralFeeCollected").withArgs(referrerTwo.address, expectedReferrerFeeTwo)
            .and.to.emit(jackpot, "ReferralFeeCollected").withArgs(referrerThree.address, expectedReferrerFeeThree);
        });

        it("should emit the correct ReferralSchemeAdded event", async () => {
          const referralSchemeId = calculateReferralSchemeId(subjectReferrers, subjectReferralSplitBps);

          await expect(subject()).to.emit(jackpot, "ReferralSchemeAdded").withArgs(
            referralSchemeId,
            subjectReferrers,
            subjectReferralSplitBps
          );
        });
  
        describe("when a duplicate ticket is bought", async () => {
          beforeEach(async () => {
            subjectTickets = [
              {
                normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
                bonusball: BigInt(1)
              } as Ticket,
              {
                normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
                bonusball: BigInt(1)
              } as Ticket,
            ];
          });

          it("should correctly update the DrawingState for the current drawing", async () => {
            const preDrawingState: DrawingState = await jackpot.getDrawingState(1);

            await subject();
    
            const actualDrawingState: DrawingState = await jackpot.getDrawingState(1);
    
            expect(actualDrawingState.globalTicketsBought).to.eq(BigInt(2));
            expect(actualDrawingState.lpEarnings).to.eq(BigInt(subjectTickets.length) * ticketPrice * (PRECISE_UNIT - referralFee) / PRECISE_UNIT);
            expect(actualDrawingState.prizePool).to.eq(preDrawingState.prizePool + ticketPrice * (PRECISE_UNIT - lpEdgeTarget) / PRECISE_UNIT);
          });

          it("should return the correct ticket ids", async () => {
            const ticketIds = await subjectStaticCall();
    
            const expectedTicketIdOne = calculateTicketId(1, 1, calculatePackedTicket(subjectTickets[0], BigInt(normalBallMax)));
            const expectedTicketIdTwo = calculateTicketId(1, 2, calculatePackedTicket(subjectTickets[1], BigInt(normalBallMax)));
    
            expect(ticketIds).to.deep.equal([expectedTicketIdOne, expectedTicketIdTwo]);
          });

          it("should correctly update the DrawingEntries for the current drawing", async () => {
            await subject();

            const subsetCount: ComboCount = await jackpot.getSubsetCount(1, subjectTickets[0].normals, subjectTickets[0].bonusball);
            expect(subsetCount.count).to.eq(BigInt(1));
            expect(subsetCount.dupCount).to.eq(BigInt(1));
          });
        });

        describe("when no referral scheme", async () => {
          beforeEach(async () => {
            subjectReferrers = [];
            subjectReferralSplitBps = [];
          });

          it("should correctly allocate referral share to LP earnings", async () => {
            const preDrawingState: DrawingState = await jackpot.getDrawingState(1);

            await subject();
    
            const actualDrawingState: DrawingState = await jackpot.getDrawingState(1);
    
            expect(actualDrawingState.globalTicketsBought).to.eq(BigInt(2));
            expect(actualDrawingState.lpEarnings).to.eq(preDrawingState.lpEarnings + BigInt(subjectTickets.length) * ticketPrice);
          });

          it("should correctly update the ticket mapping to have no referral scheme", async () => {
            await subject();
    
            const ticketOne = await jackpotNFT.tickets(calculateTicketId(1, 1, calculatePackedTicket(subjectTickets[0], BigInt(normalBallMax))));
            const ticketTwo = await jackpotNFT.tickets(calculateTicketId(1, 2, calculatePackedTicket(subjectTickets[1], BigInt(normalBallMax))));
    
            expect(ticketOne.drawingId).to.eq(1);
            expect(ticketOne.packedTicket).to.eq(calculatePackedTicket(subjectTickets[0], BigInt(normalBallMax)));
            expect(ticketOne.referralScheme).to.eq(ZERO_BYTES32);
    
            expect(ticketTwo.drawingId).to.eq(1);
            expect(ticketTwo.packedTicket).to.eq(calculatePackedTicket(subjectTickets[1], BigInt(normalBallMax)));
            expect(ticketTwo.referralScheme).to.eq(ZERO_BYTES32);
          });
        });
  
        describe("when the ticket count is zero", async () => {
          beforeEach(async () => {
            subjectTickets = [];
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidTicketCount");
          });
        });

        describe("when buyer has not approved tokens", async () => {
          beforeEach(async () => {
            await usdcMock.connect(buyerOne.wallet).approve(jackpot.getAddress(), ZERO);
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(usdcMock, "ERC20InsufficientAllowance");
          });
        });
  
        describe("when the ticket does not have 5 normal balls", async () => {
          beforeEach(async () => {
            subjectTickets = [
              {
                normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5), BigInt(6)],
                bonusball: BigInt(1)
              } as Ticket,
            ];
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidNormalsCount");
          });
        });
  
        describe("when the ticket has a bonusball that is greater than the bonusball max", async () => {
          beforeEach(async () => {
            const bonusballMax = (await jackpot.getDrawingState(1)).bonusballMax;
            subjectTickets = [
              {
                normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
                bonusball: bonusballMax + BigInt(1)
              } as Ticket,
            ];
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidBonusball");
          });
        });
  
        describe("when the ticket has a normal ball that is greater than the normal ball max", async () => {
          beforeEach(async () => {
            subjectTickets = [
              {
                normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(31)],
                bonusball: BigInt(1)
              } as Ticket,
            ];
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWith("Invalid set selection");
          });
        });
  
        describe("when the ticket has a normal ball set to zero", async () => {
          beforeEach(async () => {
            subjectTickets = [
              {
                normals: [BigInt(0), BigInt(2), BigInt(3), BigInt(4), BigInt(31)],
                bonusball: BigInt(1)
              } as Ticket,
            ];
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWith("Invalid set selection");
          });
        });

        describe("when the ticket has a bonusball set to zero", async () => {
          beforeEach(async () => {
            subjectTickets = [
              {
                normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
                bonusball: BigInt(0)
              } as Ticket,
            ];
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidBonusball");
          });
        });
  
        describe("when the ticket has a duplicate normal ball", async () => {
          beforeEach(async () => {
            subjectTickets = [
              {
                normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(3)],
                bonusball: BigInt(1)
              } as Ticket,
            ];
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWith("Duplicate number in set");
          });
        });

        describe("when no prize pool is funded", async () => {
          beforeEach(async () => {
            await jackpot.connect(lpOne.wallet).initiateWithdraw(usdc(2000000));
            await time.increase(drawingDurationInSeconds);
            const drawingState = await jackpot.getDrawingState(1);
            await jackpot.runJackpot({ value: entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7)) });

            const winningNumbers = [[BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], [BigInt(6)]];
            await entropyProvider.randomnessCallback(winningNumbers);
            await jackpot.connect(lpOne.wallet).finalizeWithdraw();
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "NoPrizePool");
          });
        });
  
        describe("when the recipient is the zero address", async () => {
          beforeEach(async () => {
            subjectRecipient = ADDRESS_ZERO;
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidRecipient");
          });
        });

        describe("when the ticket purchases are disabled", async () => {
          beforeEach(async () => {
            await jackpot.connect(owner.wallet).disableTicketPurchases();
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "TicketPurchasesDisabled");
          });
        });
  
        describe("when the referrer count does not match the referral split count", async () => {
          beforeEach(async () => {
            subjectReferrers = [referrerOne.address, referrerTwo.address];
            subjectReferralSplitBps = [ether(.3333), ether(.3333), ether(.3334)];
          });
          
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "ReferralSplitLengthMismatch");
          });
        });
  
        describe("when the referral split bps do not sum to 10000", async () => {
          beforeEach(async () => {
            subjectReferralSplitBps = [BigInt(3333), BigInt(3333), BigInt(3333)];
          });
          
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "ReferralSplitSumInvalid");
          });
        });
  
        describe("when the referrer count exceeds the max referrers", async () => {
          beforeEach(async () => {
            subjectReferrers = [referrerOne.address, referrerTwo.address, referrerThree.address, buyerOne.address, owner.address, await entropyProvider.getAddress()];
            subjectReferralSplitBps = [BigInt(3000), BigInt(3000), BigInt(3000), BigInt(1), BigInt(1), BigInt(1)];
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "TooManyReferrers");
          });
        });
  
        describe("when the referrer is the zero address", async () => {
          beforeEach(async () => {
            subjectReferrers = [ADDRESS_ZERO, referrerTwo.address, referrerThree.address];
            subjectReferralSplitBps = [ether(.3333), ether(.3333), ether(.3334)];
          });
          
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "ZeroAddress");
          });
        });
  
        describe("when the referral split bps are zero", async () => {
  
          beforeEach(async () => {
            subjectReferralSplitBps = [BigInt(5000), BigInt(5000), BigInt(0)];
          });
          
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidReferralSplitBps");
          });
        });
  
        // describe("when the ticket purchases are disabled", async () => {
        //   beforeEach(async () => {
        //     await jackpot.connect(owner.wallet).disableTicketPurchases();
        //   });
  
        //   it("should revert", async () => {
        //     await expect(subject()).to.be.revertedWithCustomError(jackpot, "TicketPurchasesDisabled");
        //   });
        // });
  
        describe("when the jackpot is locked", async () => {
          beforeEach(async () => {
            await jackpot.connect(owner.wallet).lockJackpot();
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "JackpotLocked");
          });
        });

        describe("when emergency mode is enabled", async () => {
          beforeEach(async () => {
            await jackpot.connect(owner.wallet).enableEmergencyMode();
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "EmergencyEnabled");
          });
        });

        describe("when the reentrancy protection is violated", async () => {
          beforeEach(async () => {
            await usdcMock.setCallbackTarget(await jackpot.getAddress());
            const callbackData = jackpot.interface.encodeFunctionData(
              "buyTickets",
              [
                subjectTickets,
                subjectRecipient,
                subjectReferrers,
                subjectReferralSplitBps,
                subjectSource
              ]
            );
            await usdcMock.setCallbackData(callbackData)
            await usdcMock.enableCallback();
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "ReentrancyGuardReentrantCall");
          });
        });
      });
  
      describe("#runJackpot", async () => {
        let subjectTimeFastForward: bigint;
        let subjectValue: bigint;
        let subjectCaller: Account;
  
        beforeEach(async () => {
          await usdcMock.connect(buyerOne.wallet).approve(jackpot.getAddress(), usdc(5));
          await jackpot.connect(buyerOne.wallet).buyTickets(
            [
              {
                normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
                bonusball: BigInt(1)
              } as Ticket,
            ],
            buyerOne.address,
            [referrerOne.address, referrerTwo.address, referrerThree.address],
            [ether(.3333), ether(.3333), ether(.3334)],
            ethers.encodeBytes32String("test")
          );

          const drawingState = await jackpot.getDrawingState(1);
          subjectValue = entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7));
          subjectTimeFastForward = drawingDurationInSeconds
          subjectCaller = owner;
        });
  
        async function subject(): Promise<any> {
          await time.increase(subjectTimeFastForward);
          return await jackpot.connect(subjectCaller.wallet).runJackpot(
            { value: subjectValue }
          );
        }
  
        it("should correctly set the jackpotLock for the drawing", async () => {
          await subject();
  
          const actualJackpotLock = (await jackpot.getDrawingState(1)).jackpotLock;
          expect(actualJackpotLock).to.be.true;
        });
  
        it("should call the entropy provider with the correct parameters", async () => {
          await subject();
  
          const requestId = ethers.zeroPadValue(ethers.toBeHex(1), 32); // This matches bytes32(uint256(1)) from the mock
          const pendingRequest = await entropyProvider.getPendingRequest(requestId);
          const drawingState = await jackpot.getDrawingState(1);
  
          expect(pendingRequest.setRequests[0].minRange).to.deep.equal(BigInt(1));
          expect(pendingRequest.setRequests[0].maxRange).to.deep.equal(BigInt(drawingState.ballMax));
          expect(pendingRequest.setRequests[0].samples).to.deep.equal(BigInt(5));
          expect(pendingRequest.setRequests[0].withReplacement).to.be.false;
          expect(pendingRequest.setRequests[1].minRange).to.deep.equal(BigInt(1));
          expect(pendingRequest.setRequests[1].maxRange).to.deep.equal(BigInt(drawingState.bonusballMax));
          expect(pendingRequest.setRequests[1].samples).to.deep.equal(BigInt(1));
          expect(pendingRequest.setRequests[1].withReplacement).to.be.false;

          expect(pendingRequest.callback).to.eq(await jackpot.getAddress());
          expect(pendingRequest.selector).to.eq(jackpot.interface.getFunction("scaledEntropyCallback").selector);
          expect(pendingRequest.context).to.eq("0x");
        });

        it("should emit the correct JackpotRunRequested event", async () => {
          const drawingState = await jackpot.getDrawingState(1);
          const entropyGasLimit = entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax;
          const fee = entropyFee + (entropyGasLimit * BigInt(1e7));
          await expect(subject()).to.emit(jackpot, "JackpotRunRequested").withArgs(
            1,
            entropyGasLimit,
            fee
          );
        });

        describe("when excess value is sent", async () => {
          beforeEach(async () => {
            const drawingState = await jackpot.getDrawingState(1);
            subjectValue = entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7)) + ether(0.1);
          });

          it("should refund the excess ETH to the caller", async () => {
            const preBalance = await ethers.provider.getBalance(owner.address);
            const drawingState = await jackpot.getDrawingState(1);
            
            const tx = await subject();
            const receipt = await tx.wait();
            const gasUsed = receipt!.gasUsed * receipt!.gasPrice;
            
            const postBalance = await ethers.provider.getBalance(owner.address);
            const fee = entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7));
            const expectedBalance = preBalance - fee - BigInt(gasUsed);
            
            expect(postBalance).to.eq(expectedBalance);
          });
        });

        describe("when reentrancy protection is violated", async () => {
          let ethRejectingContract: ETHRejectingContract;

          beforeEach(async () => {
            const deployer = new DeployHelper(owner.wallet);
            ethRejectingContract = await deployer.deployETHRejectingContract();
            const drawingState = await jackpot.getDrawingState(1);
            
            // Fund the contract with enough ETH to call runJackpot (while it accepts ETH)
            await owner.wallet.sendTransaction({
              to: await ethRejectingContract.getAddress(),
              value:  entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7)) + ether(0.1)
            });
            
            // Now set it to reject ETH transfers (this will cause the refund to fail)
            await ethRejectingContract.setCallbackTarget(await jackpot.getAddress());
            const callbackData = jackpot.interface.encodeFunctionData(
              "runJackpot",
              []
            );
            await ethRejectingContract.setCallbackData(callbackData);
            
            subjectValue =  entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7)) + ether(0.1);
            await time.increase(drawingDurationInSeconds);
          });

          it("should revert with 'Transfer failed'", async () => {
            // This test verifies that when runJackpot tries to refund excess ETH
            // and the refund fails, the entire transaction reverts with "Transfer failed"
            await expect(
              ethRejectingContract.callRunJackpot(
                await jackpot.getAddress(),
                subjectValue
              )
            ).to.be.revertedWithCustomError(jackpot, "ReentrancyGuardReentrantCall");
          });
        });

        describe("when excess value is sent but refund fails", async () => {
          let ethRejectingContract: ETHRejectingContract;

          beforeEach(async () => {
            const deployer = new DeployHelper(owner.wallet);
            ethRejectingContract = await deployer.deployETHRejectingContract();
            const drawingState = await jackpot.getDrawingState(1);
            
            // Fund the contract with enough ETH to call runJackpot (while it accepts ETH)
            await owner.wallet.sendTransaction({
              to: await ethRejectingContract.getAddress(),
              value: entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7)) + ether(0.1)
            });
            
            // Now set it to reject ETH transfers (this will cause the refund to fail)
            await ethRejectingContract.setRejectETH(true);
            
            subjectValue = entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7)) + ether(0.1);
            await time.increase(drawingDurationInSeconds);
          });

          it("should revert with 'Transfer failed'", async () => {
            // This test verifies that when runJackpot tries to refund excess ETH
            // and the refund fails, the entire transaction reverts with "Transfer failed"
            await expect(
              ethRejectingContract.callRunJackpot(
                await jackpot.getAddress(),
                subjectValue
              )
            ).to.be.revertedWith("Refund transfer failed");
          });
        });
  
        describe("when the drawing is not due", async () => {
          beforeEach(async () => {
            subjectTimeFastForward = drawingDurationInSeconds - BigInt(10);
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "DrawingNotDue");
          });
        });

        describe("when emergency mode is enabled", async () => {
          beforeEach(async () => {
            await jackpot.connect(owner.wallet).enableEmergencyMode();
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "EmergencyEnabled");
          });
        });
  
        describe("when the jackpot is locked", async () => {
          beforeEach(async () => {
            await subject();
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "JackpotLocked");
          });
        });
  
        describe("when not enough value is sent", async () => {
          beforeEach(async () => {
            subjectValue = entropyFee - BigInt(1);
          });
  
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "InsufficientEntropyFee");
          });
        });
      });

      describe("#scaledEntropyCallback", async () => {
        let subjectRandomNumbers: bigint[][];
        let subjectCaller: Account;

        let isJackpotRun: boolean = true;

        beforeEach(async () => {
          await usdcMock.connect(buyerOne.wallet).approve(jackpot.getAddress(), usdc(5));
          await jackpot.connect(buyerOne.wallet).buyTickets(
            [
              {
                normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
                bonusball: BigInt(6)
              } as Ticket,
            ],
            buyerOne.address,
            [referrerOne.address, referrerTwo.address, referrerThree.address],
            [ether(.3333), ether(.3333), ether(.3334)],
            ethers.encodeBytes32String("test")
          );

          if (isJackpotRun) {
            await time.increase(drawingDurationInSeconds);
            const drawingState = await jackpot.getDrawingState(1);
            await jackpot.runJackpot({ value: entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7)) });
          }

          subjectRandomNumbers = [[BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], [BigInt(6)]];
          subjectCaller = buyerOne;
        });

        async function subject(): Promise<any> {
          return await entropyProvider.connect(subjectCaller.wallet).randomnessCallback(subjectRandomNumbers);
        }

        async function subjectIncorrectCaller() {
          return await jackpot.connect(user.wallet).scaledEntropyCallback(
            ethers.encodeBytes32String("test"),
            subjectRandomNumbers,
            ethers.encodeBytes32String("test")
          );
        }

        it("should correctly set the accumulator for the drawing", async () => {
          const preDrawingState = await jackpot.getDrawingState(1);
          const preLpDrawingState = await jackpotLPManager.getLPDrawingState(1);
          const winners = [BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(1)];
          const duplicates = [BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0)];
          const expectedTierInfo = calculateTotalDrawingPayout(preDrawingState.prizePool, preDrawingState.ballMax, preDrawingState.bonusballMax, winners, duplicates, minimumPayout, minPayoutTiers, premiumTierWeights);

          await subject();

          const actualAccumulator = await jackpotLPManager.getDrawingAccumulator(1);
          const expectedAccumulator = (await jackpotLPManager.getDrawingAccumulator(0)) * (preLpDrawingState.lpPoolTotal - expectedTierInfo.totalPayout + preDrawingState.lpEarnings) / (preLpDrawingState.lpPoolTotal);
          expect(actualAccumulator).to.be.equal(expectedAccumulator);
        });

        it("should set the correct drawingState for current drawing", async () => {
          await subject();

          const expectedWinningTicket = calculatePackedTicket({
            normals: subjectRandomNumbers[0],
            bonusball: subjectRandomNumbers[1][0]
          }, BigInt(30));
          
          const actualWinningTicket = (await jackpot.getDrawingState(1)).winningTicket;
          const currentDrawingId = await jackpot.currentDrawingId();
          expect(actualWinningTicket).to.be.equal(expectedWinningTicket);
          expect(currentDrawingId).to.be.equal(BigInt(2));
        });

        it("should set the correct drawingState for next drawing", async () => {
          const currentDrawingState = await jackpot.getDrawingState(1);
          const currentLpDrawingState = await jackpotLPManager.getLPDrawingState(1);
          const winners = [BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(1)];
          const duplicates = [BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0)];
          const expectedTierInfo = calculateTotalDrawingPayout(
            currentDrawingState.prizePool,
            currentDrawingState.ballMax,
            currentDrawingState.bonusballMax,
            winners,
            duplicates,
            minimumPayout,
            minPayoutTiers,
            premiumTierWeights
          );

          await subject();

          const actualDrawingState: DrawingState = await jackpot.getDrawingState(2);
          const actualLpDrawingState = await jackpotLPManager.getLPDrawingState(2);
          const expectedLpPoolTotal = currentLpDrawingState.lpPoolTotal + currentDrawingState.lpEarnings - expectedTierInfo.totalPayout;
          const expectedPrizePool = expectedLpPoolTotal*(PRECISE_UNIT-reserveRatio)/PRECISE_UNIT;
          const expectedBonusballMax = calculateBonusballMax(expectedPrizePool, normalBallMax, ticketPrice, lpEdgeTarget, bonusballMin);

          expect(actualLpDrawingState.lpPoolTotal).to.be.equal(expectedLpPoolTotal);
          expect(actualDrawingState.prizePool).to.be.equal(expectedPrizePool);
          expect(actualDrawingState.drawingTime).to.be.equal(currentDrawingState.drawingTime + drawingDurationInSeconds);
          expect(actualDrawingState.edgePerTicket).to.be.equal(lpEdgeTarget * ticketPrice / PRECISE_UNIT);
          expect(actualDrawingState.ticketPrice).to.be.equal(ticketPrice);
          expect(actualDrawingState.referralWinShare).to.be.equal(referralWinShare);
          expect(actualDrawingState.jackpotLock).to.be.false;
          expect(actualLpDrawingState.pendingDeposits).to.be.equal(0);
          expect(actualLpDrawingState.pendingWithdrawals).to.be.equal(0);
          expect(actualDrawingState.ballMax).to.be.equal(normalBallMax);
          expect(actualDrawingState.bonusballMax).to.be.equal(expectedBonusballMax);
          expect(actualDrawingState.globalTicketsBought).to.be.equal(0);
          expect(actualDrawingState.lpEarnings).to.be.equal(0);
          expect(actualDrawingState.winningTicket).to.be.equal(BigInt(0));
        });

        it("should set the correct tier payouts for current drawing", async () => {
          await subject();

          const actualTierInfo = await payoutCalculator.getDrawingTierPayouts(BigInt(1));
          const currentDrawingState = await jackpot.getDrawingState(1);
          const winners = [BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(1)];
          const duplicates = [BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0)];
          const expectedTierInfo = calculateTotalDrawingPayout(currentDrawingState.prizePool, currentDrawingState.ballMax, currentDrawingState.bonusballMax, winners, duplicates, minimumPayout, minPayoutTiers, premiumTierWeights);

          expect(actualTierInfo).to.deep.equal(expectedTierInfo.tierPayouts);
        });

        it("should set the correct tierInfo for next drawing", async () => {
          await subject();

          const actualTierInfo: DrawingTierInfo = await payoutCalculator.getDrawingTierInfo(BigInt(2));
          expect(actualTierInfo.minPayout).to.be.equal(minimumPayout);
          expect(actualTierInfo.minPayoutTiers).to.deep.equal(minPayoutTiers);
          expect(actualTierInfo.premiumTierWeights).to.deep.equal(premiumTierWeights);
        });

        it("should emit the correct JackpotSettled event", async () => {
          const currentDrawingState = await jackpot.getDrawingState(1);
          const currentLpDrawingState = await jackpotLPManager.getLPDrawingState(1);
          const winners = [BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(1)];
          const duplicates = [BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0)];
          const expectedTierInfo = calculateTotalDrawingPayout(currentDrawingState.prizePool, currentDrawingState.ballMax, currentDrawingState.bonusballMax, winners, duplicates, minimumPayout, minPayoutTiers, premiumTierWeights);
          const expectedWinningTicket = calculatePackedTicket({
            normals: subjectRandomNumbers[0],
            bonusball: subjectRandomNumbers[1][0]
          }, BigInt(30));
          const postDrawLpValue = currentLpDrawingState.lpPoolTotal + currentDrawingState.lpEarnings - expectedTierInfo.totalPayout;
          const newAccumulatorValue = (await jackpotLPManager.getDrawingAccumulator(0)) * postDrawLpValue / currentLpDrawingState.lpPoolTotal;

          await expect(subject()).to.emit(jackpot, "JackpotSettled").withArgs(
            1,
            currentDrawingState.globalTicketsBought,
            expectedTierInfo.totalPayout,
            subjectRandomNumbers[1][0],
            expectedWinningTicket,
            newAccumulatorValue
          );
        });

        it("should emit the correct WinnersCalculated event", async () => {
          const winners = [BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(1)];
          const duplicates = [BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0)];

          await expect(subject()).to.emit(jackpot, "WinnersCalculated").withArgs(
            1,
            subjectRandomNumbers[0],
            subjectRandomNumbers[1][0],
            winners,
            duplicates
          );
        });

        it("should emit the correct NewDrawingInitialized event", async () => {
          const currentDrawingState: DrawingState = await jackpot.getDrawingState(1);
          const currentLpDrawingState: LPDrawingState = await jackpotLPManager.getLPDrawingState(1);
          const winners = [BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(1)];
          const duplicates = [BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0)];
          const expectedTierInfo = calculateTotalDrawingPayout(currentDrawingState.prizePool, currentDrawingState.ballMax, currentDrawingState.bonusballMax, winners, duplicates, minimumPayout, minPayoutTiers, premiumTierWeights);
          const postDrawLpValue = currentLpDrawingState.lpPoolTotal + currentDrawingState.lpEarnings - expectedTierInfo.totalPayout;
          const newAccumulatorValue = (await jackpotLPManager.getDrawingAccumulator(0)) * postDrawLpValue / currentLpDrawingState.lpPoolTotal;
          const withdrawals = currentLpDrawingState.pendingWithdrawals * newAccumulatorValue / PRECISE_UNIT;
          const newLpValue = postDrawLpValue + currentLpDrawingState.pendingDeposits - withdrawals;
          const newPrizePool = newLpValue * (PRECISE_UNIT - reserveRatio) / PRECISE_UNIT;
          const expectedBonusballMax = calculateBonusballMax(newPrizePool, normalBallMax, ticketPrice, lpEdgeTarget, bonusballMin);
          const expectedDrawingTime = currentDrawingState.drawingTime + drawingDurationInSeconds;

          await expect(subject()).to.emit(jackpot, "NewDrawingInitialized").withArgs(
            2,
            newLpValue,
            newPrizePool,
            ticketPrice,
            normalBallMax,
            expectedBonusballMax,
            referralWinShare,
            expectedDrawingTime
          );
        });

        describe("when the net LP winnings are positive but do not exceed the protocol fee threshold", async () => {          
          beforeEach(async () => {
            subjectRandomNumbers = [[BigInt(7), BigInt(8), BigInt(9), BigInt(10), BigInt(11)], [BigInt(10)]];
          });

          it("no funds should be transferred to the protocol fee address", async () => {
            const preProtocolFeeAddressBalance = await usdcMock.balanceOf(owner.address);
            await subject();
            const postProtocolFeeAddressBalance = await usdcMock.balanceOf(owner.address);
            expect(postProtocolFeeAddressBalance).to.be.equal(preProtocolFeeAddressBalance);
          });

          it("should emit the ProtocolFeeCollected event with 0 amount", async () => {
            const currentDrawingId = await jackpot.currentDrawingId();
            await expect(subject()).to.emit(jackpot, "ProtocolFeeCollected").withArgs(currentDrawingId, 0);
          });
        });

        describe("when the net LP winnings are positive and exceed the protocol fee threshold", async () => {          
          beforeEach(async () => {
            subjectRandomNumbers = [[BigInt(7), BigInt(8), BigInt(9), BigInt(10), BigInt(11)], [BigInt(10)]];
            await jackpot.connect(owner.wallet).setProtocolFeeThreshold(usdc(0.1));
          });

          it("should be transferred to the protocol fee address", async () => {
            const preProtocolFeeAddressBalance = await usdcMock.balanceOf(owner.address);
            await subject();

            // .935 USDC because the referral fee is 6.5% then we subtract the fee threshold of .1 USDC
            const applyReferralFee = ticketPrice * (PRECISE_UNIT - referralFee) / PRECISE_UNIT;
            const expectedProtocolFee = (applyReferralFee - usdc(0.1)) * protocolFee / PRECISE_UNIT;
            const postProtocolFeeAddressBalance = await usdcMock.balanceOf(owner.address);
            expect(postProtocolFeeAddressBalance).to.be.equal(expectedProtocolFee + preProtocolFeeAddressBalance);
          });

          it("should emit the ProtocolFeeCollected event with the correct amount", async () => {
            const currentDrawingId = await jackpot.currentDrawingId();
            // .935 USDC because the referral fee is 6.5% then we subtract the fee threshold of .1 USDC
            const applyReferralFee = ticketPrice * (PRECISE_UNIT - referralFee) / PRECISE_UNIT;
            const expectedProtocolFee = (applyReferralFee - usdc(0.1)) * protocolFee / PRECISE_UNIT;
            await expect(subject()).to.emit(jackpot, "ProtocolFeeCollected").withArgs(currentDrawingId, expectedProtocolFee);
          });
        });

        describe("when the caller is not the entropy provider", async () => {          
          it("should revert", async () => {
            await expect(subjectIncorrectCaller()).to.be.revertedWithCustomError(jackpot, "UnauthorizedEntropyCaller");
          });
        });

        describe("when runJackpot has not been called", async () => {
          before(async () => {
            isJackpotRun = false;
          });

          after(async () => {
            isJackpotRun = true;
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "JackpotNotLocked");
          });
        });

        describe("when the reentrancy protection is violated", async () => {
          beforeEach(async () => {
            await usdcMock.setCallbackTarget(await jackpot.getAddress());
            const callbackData = jackpot.interface.encodeFunctionData(
              "scaledEntropyCallback",
              [
                ethers.encodeBytes32String("test"),
                subjectRandomNumbers,
                ethers.encodeBytes32String("test")
              ]
            );
            await usdcMock.setCallbackData(callbackData)
            await usdcMock.enableCallback();

            await jackpot.connect(owner.wallet).setProtocolFeeThreshold(usdc(0));
            subjectRandomNumbers = [[BigInt(8), BigInt(9), BigInt(10), BigInt(11), BigInt(12)], [BigInt(9)]];
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "ReentrancyGuardReentrantCall");
          });
        });
      });

      describe("#claimWinnings", async () => {
        let subjectTicketIds: bigint[];
        let subjectCaller: Account;

        let buyerOneTicketInfo: Ticket[];
        let buyerOneTicketIds: bigint[];

        let buyerTwoTicketInfo: Ticket[];
        let buyerTwoTicketIds: bigint[];

        let buyerThreeTicketInfo: Ticket[];
        let buyerThreeTicketIds: bigint[];

        let winningNumbers: bigint[][];
        let runJackpot: boolean = true;

        beforeEach(async () => {
          await usdcMock.connect(buyerOne.wallet).approve(jackpot.getAddress(), usdc(6));
          await usdcMock.connect(buyerTwo.wallet).approve(jackpot.getAddress(), usdc(5));
          await usdcMock.connect(buyerThree.wallet).approve(jackpot.getAddress(), usdc(5));

          buyerOneTicketInfo = [
            {
              normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
              bonusball: BigInt(6)
            } as Ticket,
            {
              normals: [BigInt(6), BigInt(7), BigInt(8), BigInt(9), BigInt(10)],
              bonusball: BigInt(3)
            } as Ticket,
            {
              normals: [BigInt(1), BigInt(2), BigInt(5), BigInt(7), BigInt(9)],
              bonusball: BigInt(6)
            } as Ticket,
          ];
          buyerTwoTicketInfo = [
            {
              normals: [BigInt(6), BigInt(7), BigInt(8), BigInt(9), BigInt(10)],
              bonusball: BigInt(6)
            } as Ticket,
            {
              normals: [BigInt(6), BigInt(7), BigInt(8), BigInt(10), BigInt(normalBallMax)],
              bonusball: BigInt(6)
            } as Ticket,
          ];

          buyerThreeTicketInfo = [
            {
              normals: [BigInt(5), BigInt(7), BigInt(8), BigInt(9), BigInt(10)],
              bonusball: BigInt(3)
            } as Ticket,
          ];

          // buyer one
          buyerOneTicketIds = await jackpot.connect(buyerOne.wallet).buyTickets.staticCall(
            buyerOneTicketInfo,
            buyerOne.address,
            [referrerOne.address, referrerTwo.address, referrerThree.address],
            [ether(.3333), ether(.3333), ether(.3334)],
            ethers.encodeBytes32String("test")
          );

          await jackpot.connect(buyerOne.wallet).buyTickets(
            buyerOneTicketInfo,
            buyerOne.address,
            [referrerOne.address, referrerTwo.address, referrerThree.address],
            [ether(.3333), ether(.3333), ether(.3334)],
            ethers.encodeBytes32String("test")
          );

          // buyer two
          buyerTwoTicketIds = await jackpot.connect(buyerTwo.wallet).buyTickets.staticCall(
            buyerTwoTicketInfo,
            buyerTwo.address,
            [],
            [],
            ethers.encodeBytes32String("test")
          );

          await jackpot.connect(buyerTwo.wallet).buyTickets(
            buyerTwoTicketInfo,
            buyerTwo.address,
            [],
            [],
            ethers.encodeBytes32String("test")
          );

          // buyer three
          buyerThreeTicketIds = await jackpot.connect(buyerThree.wallet).buyTickets.staticCall(
            buyerThreeTicketInfo,
            buyerThree.address,
            [],
            [],
            ethers.encodeBytes32String("test")
          );

          await jackpot.connect(buyerThree.wallet).buyTickets(
            buyerThreeTicketInfo,
            buyerThree.address,
            [],
            [],
            ethers.encodeBytes32String("test")
          );

          if (runJackpot) {
            await time.increase(drawingDurationInSeconds);
            const drawingState = await jackpot.getDrawingState(1);
            await jackpot.runJackpot({ value: entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7)) });

            winningNumbers = [[BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], [BigInt(6)]];
            await entropyProvider.randomnessCallback(winningNumbers);
          }

          subjectTicketIds = [buyerOneTicketIds[0]];
          subjectCaller = buyerOne;
        });

        async function subject(): Promise<any> {
          return await jackpot.connect(subjectCaller.wallet).claimWinnings(subjectTicketIds);
        }

        it("should transfer the correct amount to the caller", async () => {
          const preBuyerBalance = await usdcMock.balanceOf(buyerOne.address);
          const preContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());

          await subject();

          const expectedWinningAmount = await payoutCalculator.getTierPayout(1, 11);
          const expectedReferrerFee = expectedWinningAmount * referralWinShare / PRECISE_UNIT;

          const postBuyerBalance = await usdcMock.balanceOf(buyerOne.address);
          const postContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());

          expect(postBuyerBalance).to.be.equal(preBuyerBalance + expectedWinningAmount - expectedReferrerFee);
          expect(postContractBalance).to.be.equal(preContractBalance - expectedWinningAmount + expectedReferrerFee);
        });

        it("should update the referrer fees", async () => {
          const preReferrerOneFees = await jackpot.referralFees(referrerOne.address);
          const preReferrerTwoFees = await jackpot.referralFees(referrerTwo.address);
          const preReferrerThreeFees = await jackpot.referralFees(referrerThree.address);
          
          await subject();

          const postReferrerOneFees = await jackpot.referralFees(referrerOne.address);
          const postReferrerTwoFees = await jackpot.referralFees(referrerTwo.address);
          const postReferrerThreeFees = await jackpot.referralFees(referrerThree.address);

          const expectedWinningAmount = await payoutCalculator.getTierPayout(1, 11);
          const expectedReferrerFeeOne = expectedWinningAmount * referralWinShare * ether(.3333) / (PRECISE_UNIT * PRECISE_UNIT);
          const expectedReferrerFeeTwo = expectedWinningAmount * referralWinShare * ether(.3333) / (PRECISE_UNIT * PRECISE_UNIT);
          const expectedReferrerFeeThree = expectedWinningAmount * referralWinShare * ether(.3334) / (PRECISE_UNIT * PRECISE_UNIT);

          expect(postReferrerOneFees).to.be.equal(preReferrerOneFees + expectedReferrerFeeOne);
          expect(postReferrerTwoFees).to.be.equal(preReferrerTwoFees + expectedReferrerFeeTwo);
          expect(postReferrerThreeFees).to.be.equal(preReferrerThreeFees + expectedReferrerFeeThree);
        });

        it("should burn the ticket and update user tickets", async () => {
          await subject();

          const userTickets: ExtendedTrackedTicket[] = await jackpotNFT.getUserTickets(buyerOne.address, 1);

          expect(userTickets.length).to.be.equal(2);
          expect(userTickets[0].ticket.packedTicket).to.be.equal(calculatePackedTicket(buyerOneTicketInfo[2], BigInt(normalBallMax)));
          expect(userTickets[1].ticket.packedTicket).to.be.equal(calculatePackedTicket(buyerOneTicketInfo[1], BigInt(normalBallMax)));
          expect(userTickets[0].normals).to.deep.equal(buyerOneTicketInfo[2].normals);
          expect(userTickets[1].normals).to.deep.equal(buyerOneTicketInfo[1].normals);
          expect(userTickets[0].bonusball).to.equal(buyerOneTicketInfo[2].bonusball);
          expect(userTickets[1].bonusball).to.equal(buyerOneTicketInfo[1].bonusball);

          await expect(jackpotNFT.ownerOf(subjectTicketIds[0])).to.revertedWithCustomError(jackpotNFT, "TokenDoesNotExist");
        });

        it("should emit the correct TicketWinningsClaimed event", async () => {
          const expectedWinningAmount = await payoutCalculator.getTierPayout(1, 11);
          const expectedReferrerFee = expectedWinningAmount * referralWinShare / PRECISE_UNIT;

          await expect(subject()).to.emit(jackpot, "TicketWinningsClaimed").withArgs(
            subjectCaller.address,
            BigInt(1),
            subjectTicketIds[0],
            BigInt(5),
            true,
            expectedWinningAmount - expectedReferrerFee
          );
        });

        it("should emit ReferralFeeCollected events when claiming winning tickets with referrals", async () => {
          const expectedWinningAmount = await payoutCalculator.getTierPayout(1, 11);
          const expectedReferrerShare = expectedWinningAmount * referralWinShare / PRECISE_UNIT;
          const expectedReferrerFeeOne = expectedReferrerShare * ether(.3333) / PRECISE_UNIT;
          const expectedReferrerFeeTwo = expectedReferrerShare * ether(.3333) / PRECISE_UNIT;
          const expectedReferrerFeeThree = expectedReferrerShare * ether(.3334) / PRECISE_UNIT;

          await expect(subject())
            .to.emit(jackpot, "ReferralFeeCollected").withArgs(referrerOne.address, expectedReferrerFeeOne)
            .and.to.emit(jackpot, "ReferralFeeCollected").withArgs(referrerTwo.address, expectedReferrerFeeTwo)
            .and.to.emit(jackpot, "ReferralFeeCollected").withArgs(referrerThree.address, expectedReferrerFeeThree);
        });

        describe("when the referrer win share changes before the ticket is claimed", async () => {
          beforeEach(async () => {
            await jackpot.setReferralWinShare(ether(0.08));
          });

          it("should transfer the correct amount to the caller (should be the same as previous test)", async () => {
            const preBuyerBalance = await usdcMock.balanceOf(buyerOne.address);
            const preContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());
  
            await subject();
  
            const expectedWinningAmount = await payoutCalculator.getTierPayout(1, 11);
            const expectedReferrerFee = expectedWinningAmount * referralWinShare / PRECISE_UNIT;
  
            const postBuyerBalance = await usdcMock.balanceOf(buyerOne.address);
            const postContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());
  
            expect(postBuyerBalance).to.be.equal(preBuyerBalance + expectedWinningAmount - expectedReferrerFee);
            expect(postContractBalance).to.be.equal(preContractBalance - expectedWinningAmount + expectedReferrerFee);
          });
  
          it("should update the referrer fees (should be the same as previous test)", async () => {
            const preReferrerOneFees = await jackpot.referralFees(referrerOne.address);
            const preReferrerTwoFees = await jackpot.referralFees(referrerTwo.address);
            const preReferrerThreeFees = await jackpot.referralFees(referrerThree.address);
            
            await subject();
  
            const postReferrerOneFees = await jackpot.referralFees(referrerOne.address);
            const postReferrerTwoFees = await jackpot.referralFees(referrerTwo.address);
            const postReferrerThreeFees = await jackpot.referralFees(referrerThree.address);
  
            const expectedWinningAmount = await payoutCalculator.getTierPayout(1, 11);
            const expectedReferrerFeeOne = expectedWinningAmount * referralWinShare * ether(.3333) / (PRECISE_UNIT * PRECISE_UNIT);
            const expectedReferrerFeeTwo = expectedWinningAmount * referralWinShare * ether(.3333) / (PRECISE_UNIT * PRECISE_UNIT);
            const expectedReferrerFeeThree = expectedWinningAmount * referralWinShare * ether(.3334) / (PRECISE_UNIT * PRECISE_UNIT);
  
            expect(postReferrerOneFees).to.be.equal(preReferrerOneFees + expectedReferrerFeeOne);
            expect(postReferrerTwoFees).to.be.equal(preReferrerTwoFees + expectedReferrerFeeTwo);
            expect(postReferrerThreeFees).to.be.equal(preReferrerThreeFees + expectedReferrerFeeThree);
          });
        });

        describe("when a passed ticket is not a winning ticket", async () => {
          beforeEach(async () => {
            subjectTicketIds = [buyerOneTicketIds[1]];
          });

          it("should return the correct winnings", async () => {
            const preBuyerBalance = await usdcMock.balanceOf(buyerOne.address);
            const preContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());

            await subject();

            const actualPostBuyerBalance = await usdcMock.balanceOf(buyerOne.address);
            const actualPostContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());
            expect(actualPostBuyerBalance).to.be.equal(preBuyerBalance);
            expect(actualPostContractBalance).to.be.equal(preContractBalance);
          });

          it("should burn the tickets and update user tickets", async () => {
            await subject();
  
            const userTickets: ExtendedTrackedTicket[] = await jackpotNFT.getUserTickets(buyerOne.address, 1);

            expect(userTickets.length).to.be.equal(2);
            expect(userTickets[0].ticket.packedTicket).to.be.equal(calculatePackedTicket(buyerOneTicketInfo[0], BigInt(normalBallMax)));
            expect(userTickets[1].ticket.packedTicket).to.be.equal(calculatePackedTicket(buyerOneTicketInfo[2], BigInt(normalBallMax)));
            expect(userTickets[0].normals).to.deep.equal(buyerOneTicketInfo[0].normals);
            expect(userTickets[1].normals).to.deep.equal(buyerOneTicketInfo[2].normals);
            expect(userTickets[0].bonusball).to.equal(buyerOneTicketInfo[0].bonusball);
            expect(userTickets[1].bonusball).to.equal(buyerOneTicketInfo[2].bonusball);
            await expect(jackpotNFT.ownerOf(subjectTicketIds[0])).to.revertedWithCustomError(jackpotNFT, "TokenDoesNotExist");
          });
        });

        describe("when a passed ticket contains the normal ball max and a matching bonusball", async () => {
          beforeEach(async () => {
            subjectTicketIds = [buyerTwoTicketIds[1]];
            subjectCaller = buyerTwo;
          });

          it("should return the correct winnings recognizing it as a winning ticket (note no referral fee taken)", async () => {
            const preBuyerBalance = await usdcMock.balanceOf(buyerTwo.address);
            const preContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());
            const preDrawingState = await jackpot.getDrawingState(2);

            await subject();

            const actualWinningAmount = await payoutCalculator.getTierPayout(1, 1);
            const actualReferrerFee = actualWinningAmount * referralWinShare / PRECISE_UNIT;
            const actualPostBuyerBalance = await usdcMock.balanceOf(buyerTwo.address);
            const actualPostContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());
            const actualPostDrawingState = await jackpot.getDrawingState(2);

            expect(actualPostDrawingState.lpEarnings).to.be.equal(preDrawingState.lpEarnings + actualReferrerFee);
            expect(actualWinningAmount).to.be.greaterThan(0);
            expect(actualPostBuyerBalance).to.be.equal(preBuyerBalance + actualWinningAmount - actualReferrerFee);
            expect(actualPostContractBalance).to.be.equal(preContractBalance - actualWinningAmount + actualReferrerFee);
          });

          it("should burn the tickets and update user tickets", async () => {
            await subject();
  
            const userTickets: ExtendedTrackedTicket[] = await jackpotNFT.getUserTickets(buyerTwo.address, 1);

            expect(userTickets.length).to.be.equal(1);
            expect(userTickets[0].normals).to.deep.equal(buyerTwoTicketInfo[0].normals);
            expect(userTickets[0].bonusball).to.equal(buyerTwoTicketInfo[0].bonusball);
            await expect(jackpotNFT.ownerOf(subjectTicketIds[0])).to.revertedWithCustomError(jackpotNFT, "TokenDoesNotExist");
          });

          it("should emit the correct LpEarningsUpdated event", async () => {
            const tx = await subject();
            const actualWinningAmount = await payoutCalculator.getTierPayout(1, 1);
            const actualReferrerFee = actualWinningAmount * referralWinShare / PRECISE_UNIT;

            await expect(tx).to.emit(jackpot, "LpEarningsUpdated").withArgs(2, actualReferrerFee);
          });
        });

        describe("when a passed ticket more than one matching normal ball and a low non-matching bonusball but normal ball max has been shifted", async () => {
          beforeEach(async () => {
            subjectTicketIds = [buyerThreeTicketIds[0]];
            subjectCaller = buyerThree;

            await jackpot.setNormalBallMax(BigInt(normalBallMax + BigInt(6)));
          });

          it("should not return any winnings since it only has one normal ball match, if bonusball erroneously matches it will payout", async () => {
            const preBuyerBalance = await usdcMock.balanceOf(buyerThree.address);

            await subject();

            const actualPostBuyerBalance = await usdcMock.balanceOf(buyerThree.address);

            expect(actualPostBuyerBalance).to.be.equal(preBuyerBalance);
          });
        });

        describe("when a claimed ticket does not have a referral fee", async () => {
          beforeEach(async () => {
            subjectTicketIds = [buyerTwoTicketIds[0]];
            subjectCaller = buyerTwo;
          });

          it("should return the correct winnings (note no referral fee taken)", async () => {
            const preBuyerBalance = await usdcMock.balanceOf(buyerTwo.address);
            const preContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());
            const preDrawingState = await jackpot.getDrawingState(2);

            await subject();

            const actualWinningAmount = await payoutCalculator.getTierPayout(1, 1);
            const actualReferrerFee = actualWinningAmount * referralWinShare / PRECISE_UNIT;
            const actualPostBuyerBalance = await usdcMock.balanceOf(buyerTwo.address);
            const actualPostContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());
            const actualPostDrawingState = await jackpot.getDrawingState(2);

            expect(actualWinningAmount).to.be.greaterThan(0);
            expect(actualPostBuyerBalance).to.be.equal(preBuyerBalance + actualWinningAmount - actualReferrerFee);
            expect(actualPostContractBalance).to.be.equal(preContractBalance - actualWinningAmount + actualReferrerFee);
            expect(actualPostDrawingState.lpEarnings).to.be.equal(preDrawingState.lpEarnings + actualReferrerFee);
          });

          it("should burn the tickets and update user tickets", async () => {
            await subject();
  
            const userTickets: ExtendedTrackedTicket[] = await jackpotNFT.getUserTickets(buyerTwo.address, 1);

            expect(userTickets.length).to.be.equal(1);
            expect(userTickets[0].normals).to.deep.equal(buyerTwoTicketInfo[1].normals);
            expect(userTickets[0].bonusball).to.equal(buyerTwoTicketInfo[1].bonusball);
            await expect(jackpotNFT.ownerOf(subjectTicketIds[0])).to.revertedWithCustomError(jackpotNFT, "TokenDoesNotExist");
          });

          it("should emit the correct LpEarningsUpdated event", async () => {
            const tx = await subject();
            const actualWinningAmount = await payoutCalculator.getTierPayout(1, 1);
            const actualReferrerFee = actualWinningAmount * referralWinShare / PRECISE_UNIT;

            await expect(tx).to.emit(jackpot, "LpEarningsUpdated").withArgs(2, actualReferrerFee);
          });
        });

        describe("when multiple tickets are provided", async () => {
          beforeEach(async () => {
            subjectTicketIds = [buyerOneTicketIds[0], buyerOneTicketIds[2]];
          });

          it("should transfer the correct amount to the caller", async () => {
            const preBuyerBalance = await usdcMock.balanceOf(buyerOne.address);
            const preContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());
  
            await subject();
  
            const expectedWinningAmount = await payoutCalculator.getTierPayout(1, 11) + await payoutCalculator.getTierPayout(1, 7);
            const expectedReferrerFee = expectedWinningAmount * referralWinShare / PRECISE_UNIT;
  
            const postBuyerBalance = await usdcMock.balanceOf(buyerOne.address);
            const postContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());
  
            expect(postBuyerBalance).to.be.equal(preBuyerBalance + expectedWinningAmount - expectedReferrerFee);
            expect(postContractBalance).to.be.equal(preContractBalance - expectedWinningAmount + expectedReferrerFee);
          });

          it("should update the referrer fees", async () => {
            const preReferrerOneFees = await jackpot.referralFees(referrerOne.address);
            const preReferrerTwoFees = await jackpot.referralFees(referrerTwo.address);
            const preReferrerThreeFees = await jackpot.referralFees(referrerThree.address);
            
            await subject();
  
            const postReferrerOneFees = await jackpot.referralFees(referrerOne.address);
            const postReferrerTwoFees = await jackpot.referralFees(referrerTwo.address);
            const postReferrerThreeFees = await jackpot.referralFees(referrerThree.address);
  
            const expectedReferrerShareTicketOne = ((await payoutCalculator.getTierPayout(1, 11)) * referralWinShare / PRECISE_UNIT);
            const expectedReferrerShareTicketTwo = ((await payoutCalculator.getTierPayout(1, 7)) * referralWinShare / PRECISE_UNIT);
            const expectedReferrerFeeOneTicketOne = expectedReferrerShareTicketOne * ether(.3333) / PRECISE_UNIT;
            const expectedReferrerFeeTwoTicketOne = expectedReferrerShareTicketOne * ether(.3333) / PRECISE_UNIT;
            const expectedReferrerFeeThreeTicketOne = expectedReferrerShareTicketOne * ether(.3334) / PRECISE_UNIT;
            const expectedReferrerFeeOneTicketTwo = expectedReferrerShareTicketTwo * ether(.3333) / PRECISE_UNIT;
            const expectedReferrerFeeTwoTicketTwo = expectedReferrerShareTicketTwo * ether(.3333) / PRECISE_UNIT;
            const expectedReferrerFeeThreeTicketTwo = expectedReferrerShareTicketTwo * ether(.3334) / PRECISE_UNIT;
  
            expect(postReferrerOneFees).to.be.equal(preReferrerOneFees + expectedReferrerFeeOneTicketOne + expectedReferrerFeeOneTicketTwo);
            expect(postReferrerTwoFees).to.be.equal(preReferrerTwoFees + expectedReferrerFeeTwoTicketOne + expectedReferrerFeeTwoTicketTwo);
            expect(postReferrerThreeFees).to.be.equal(preReferrerThreeFees + expectedReferrerFeeThreeTicketOne + expectedReferrerFeeThreeTicketTwo);
          });

          it("should burn the ticket and update user tickets", async () => {
            await subject();
  
            const userTickets: ExtendedTrackedTicket[] = await jackpotNFT.getUserTickets(buyerOne.address, 1);

            expect(userTickets.length).to.be.equal(1);
            expect(userTickets[0].ticket.packedTicket).to.be.equal(calculatePackedTicket(buyerOneTicketInfo[1], BigInt(normalBallMax)));
            expect(userTickets[0].normals).to.deep.equal(buyerOneTicketInfo[1].normals);
            expect(userTickets[0].bonusball).to.equal(buyerOneTicketInfo[1].bonusball);
            await expect(jackpotNFT.ownerOf(subjectTicketIds[0])).to.revertedWithCustomError(jackpotNFT, "TokenDoesNotExist");
            await expect(jackpotNFT.ownerOf(subjectTicketIds[1])).to.revertedWithCustomError(jackpotNFT, "TokenDoesNotExist");
          });
        });

        describe("when the ticket is not from a past drawing", async () => {
          before(async () => {
            runJackpot = false;
          });
          
          beforeEach(async () => {
            subjectTicketIds = [buyerOneTicketIds[0]];
          });

          afterEach(async () => {
            runJackpot = true;
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "TicketFromFutureDrawing");
          });
        });

        describe("when no tickets are provided", async () => {
          beforeEach(async () => {
            subjectTicketIds = [];
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "NoTicketsToClaim");
          });
        });

        describe("when the caller is not the ticket owner", async () => {
          beforeEach(async () => {
            subjectCaller = referrerOne;
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "NotTicketOwner");
          });
        });

        describe("when the reentrancy protection is violated", async () => {
          beforeEach(async () => {
            await usdcMock.setCallbackTarget(await jackpot.getAddress());
            const callbackData = jackpot.interface.encodeFunctionData(
              "claimWinnings",
              [subjectTicketIds]
            );
            await usdcMock.setCallbackData(callbackData)
            await usdcMock.enableCallback();
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "ReentrancyGuardReentrantCall");
          });
        });
      });

      describe("#claimReferralFees", async () => {
        let subjectCaller: Account;

        beforeEach(async () => {
          await usdcMock.connect(buyerOne.wallet).approve(jackpot.getAddress(), usdc(5));
          await jackpot.connect(buyerOne.wallet).buyTickets(
            [
              {
                normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
                bonusball: BigInt(6)
              } as Ticket,
            ],
            buyerOne.address,
            [referrerOne.address, referrerTwo.address, referrerThree.address],
            [ether(.3333), ether(.3333), ether(.3334)],
            ethers.encodeBytes32String("test")
          );

          subjectCaller = referrerOne;
        });
  
        async function subject(): Promise<any> {
          return await jackpot.connect(subjectCaller.wallet).claimReferralFees();
        }
  
        it("should transfer the correct amount to the caller", async () => {
          const preReferrerBalance = await usdcMock.balanceOf(referrerOne.address);
          const preContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());
          const referralFees = await jackpot.referralFees(referrerOne.address);
  
          await subject();
  
          const postReferrerBalance = await usdcMock.balanceOf(referrerOne.address);
          const postContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());
          const postReferralFees = await jackpot.referralFees(referrerOne.address);
  
          expect(postReferrerBalance).to.be.equal(preReferrerBalance + referralFees);
          expect(postContractBalance).to.be.equal(preContractBalance - referralFees);
          expect(postReferralFees).to.be.equal(BigInt(0));
        });

        it("should emit the correct ReferralFeesClaimed event", async () => {
          const referralFees = await jackpot.referralFees(referrerOne.address);

          await expect(subject()).to.emit(jackpot, "ReferralFeesClaimed").withArgs(
            referrerOne.address,
            referralFees
          );
        });

        describe("when the caller has no referral fees", async () => {
          beforeEach(async () => {
            subjectCaller = buyerOne;
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "NoReferralFeesToClaim");
          });
        });

        describe("when the reentrancy protection is violated", async () => {
          beforeEach(async () => {
            await usdcMock.setCallbackTarget(await jackpot.getAddress());
            const callbackData = jackpot.interface.encodeFunctionData(
              "claimReferralFees",
              []
            );
            await usdcMock.setCallbackData(callbackData)
            await usdcMock.enableCallback();
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "ReentrancyGuardReentrantCall");
          });
        });
      });

      describe("#initiateWithdraw", async () => {
        let subjectAmountToWithdrawInShares: bigint;
        let subjectCaller: Account;

        beforeEach(async () => {
          await usdcMock.connect(buyerOne.wallet).approve(jackpot.getAddress(), usdc(5));

          await jackpot.connect(buyerOne.wallet).buyTickets.staticCall(
            [
              {
                normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
                bonusball: BigInt(6)
              } as Ticket,
            ],
            buyerOne.address,
            [referrerOne.address, referrerTwo.address, referrerThree.address],
            [ether(.3333), ether(.3333), ether(.3334)],
            ethers.encodeBytes32String("test")
          );

          await jackpot.connect(buyerOne.wallet).buyTickets(
            [
              {
                normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
                bonusball: BigInt(6)
              } as Ticket,
            ],
            buyerOne.address,
            [referrerOne.address, referrerTwo.address, referrerThree.address],
            [ether(.3333), ether(.3333), ether(.3334)],
            ethers.encodeBytes32String("test")
          );

          await time.increase(drawingDurationInSeconds);
          const drawingState = await jackpot.getDrawingState(1);
          await jackpot.runJackpot({ value: entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7)) });

          const winningNumbers = [[BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], [BigInt(6)]];
          await entropyProvider.randomnessCallback(winningNumbers);

          subjectAmountToWithdrawInShares = usdc(500000);
          subjectCaller = lpOne;
        });

        async function subject(): Promise<any> {
          return await jackpot.connect(subjectCaller.wallet).initiateWithdraw(subjectAmountToWithdrawInShares);
        }

        it("should update LP state correctly", async () => {
          await subject();
          
          const actualLpState = await jackpotLPManager.getLpInfo(lpOne.address);

          expect(actualLpState.lastDeposit.amount).to.be.equal(0);
          expect(actualLpState.lastDeposit.drawingId).to.be.equal(0);
          expect(actualLpState.pendingWithdrawal.amountInShares).to.be.equal(subjectAmountToWithdrawInShares);
          expect(actualLpState.pendingWithdrawal.drawingId).to.be.equal(2);
          expect(actualLpState.consolidatedShares).to.be.equal(usdc(2000000) - subjectAmountToWithdrawInShares);
          expect(actualLpState.claimableWithdrawals).to.be.equal(0);
        });

        it("should update LPDrawingState correctly", async () => {
          await subject();
          
          const actualDrawingState = await jackpotLPManager.getLPDrawingState(2);

          expect(actualDrawingState.pendingWithdrawals).to.be.equal(subjectAmountToWithdrawInShares);
        });

        it("should emit the correct LpWithdrawInitiated event", async () => {
          await expect(subject()).to.emit(jackpotLPManager, "LpWithdrawInitiated").withArgs(
            lpOne.address,
            2,
            subjectAmountToWithdrawInShares,
            subjectAmountToWithdrawInShares
          );
        });

        describe("when there is a claimable withdrawal in the lp.pendingWithdrawal", async () => {
          beforeEach(async () => {
            await jackpot.connect(lpOne.wallet).initiateWithdraw(usdc(500000));

            await time.increase(drawingDurationInSeconds);
            const drawingState = await jackpot.getDrawingState(1);
            await jackpot.runJackpot({ value: entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7)) });

            const winningNumbers = [[BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], [BigInt(6)]];
            await entropyProvider.randomnessCallback(winningNumbers);
          });

          it("should update the claimableWithdrawals and consolidatedShares", async () => {
            await subject();

            const actualLpState = await jackpotLPManager.getLpInfo(lpOne.address);
            const drawingAccumulator = await jackpotLPManager.drawingAccumulator(1)

            expect(actualLpState.claimableWithdrawals).to.be.equal((usdc(500000) * drawingAccumulator) / PRECISE_UNIT);
            expect(actualLpState.consolidatedShares).to.be.equal(usdc(1500000) - subjectAmountToWithdrawInShares);
          });

          it("should update lp.pendingWithdrawal", async () => {
            const preLpState = await jackpotLPManager.getLpInfo(lpOne.address);
            expect(preLpState.pendingWithdrawal.amountInShares).to.be.equal(usdc(500000));
            expect(preLpState.pendingWithdrawal.drawingId).to.be.equal(2);

            await subject();

            const actualLpState = await jackpotLPManager.getLpInfo(lpOne.address);
            expect(actualLpState.pendingWithdrawal.amountInShares).to.be.equal(usdc(500000));
            expect(actualLpState.pendingWithdrawal.drawingId).to.be.equal(3);
          });

          it("should update LPDrawingState correctly", async () => {
            await subject();

            const actualDrawingState = await jackpotLPManager.getLPDrawingState(2);

            expect(actualDrawingState.pendingWithdrawals).to.be.equal(subjectAmountToWithdrawInShares);
          });
        });

        describe("when lp.pendingWithdrawal is unclaimable (drawingId >= currentDrawingId)", async () => {
          beforeEach(async () => {
            await subject();
          });

          it("should not update the claimableWithdrawals but should update consolidatedShares", async () => {
            const preLpState = await jackpotLPManager.getLpInfo(lpOne.address);

            await subject();

            const actualLpState = await jackpotLPManager.getLpInfo(lpOne.address);

            expect(actualLpState.claimableWithdrawals).to.be.equal(preLpState.claimableWithdrawals);
            expect(actualLpState.consolidatedShares).to.be.equal(usdc(1500000) - subjectAmountToWithdrawInShares);
          });

          it("should add the amount to lp.pendingWithdrawal", async () => {
            const preLpState = await jackpotLPManager.getLpInfo(lpOne.address);
            expect(preLpState.pendingWithdrawal.amountInShares).to.be.equal(usdc(500000));
            expect(preLpState.pendingWithdrawal.drawingId).to.be.equal(2);

            await subject();

            const actualLpState = await jackpotLPManager.getLpInfo(lpOne.address);
            expect(actualLpState.pendingWithdrawal.amountInShares).to.be.equal(usdc(500000) + subjectAmountToWithdrawInShares);
            expect(actualLpState.pendingWithdrawal.drawingId).to.be.equal(2);
          });

          it("should update LPDrawingState correctly", async () => {
            await subject();

            const actualDrawingState = await jackpotLPManager.getLPDrawingState(2);

            expect(actualDrawingState.pendingWithdrawals).to.be.equal(subjectAmountToWithdrawInShares*BigInt(2));
          });
        });

        describe("when no shares are provided", async () => {
          beforeEach(async () => {
            subjectAmountToWithdrawInShares = BigInt(0);
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "WithdrawAmountZero");
          });
        });

        describe("when the caller has insufficient shares", async () => {
          beforeEach(async () => {
            subjectAmountToWithdrawInShares = usdc(2000001);
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "InsufficientShares");
          });
        });

        describe("when the jackpot is locked", async () => {
          beforeEach(async () => {
            await jackpot.connect(owner.wallet).lockJackpot();
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "JackpotLocked");
          });
        });

        describe("when emergency mode is enabled", async () => {
          beforeEach(async () => {
            await jackpot.connect(owner.wallet).enableEmergencyMode();
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "EmergencyEnabled");
          });
        });
      });

      describe("#finalizeWithdraw", async () => {
        let subjectCaller: Account;

        let runJackpot: boolean = true;
        
        beforeEach(async () => {
          await usdcMock.connect(buyerOne.wallet).approve(jackpot.getAddress(), usdc(5));

          await jackpot.connect(buyerOne.wallet).buyTickets.staticCall(
            [
              {
                normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
                bonusball: BigInt(6)
              } as Ticket,
            ],
            buyerOne.address,
            [referrerOne.address, referrerTwo.address, referrerThree.address],
            [ether(.3333), ether(.3333), ether(.3334)],
            ethers.encodeBytes32String("test")
          );

          await jackpot.connect(buyerOne.wallet).buyTickets(
            [
              {
                normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
                bonusball: BigInt(6)
              } as Ticket,
            ],
            buyerOne.address,
            [referrerOne.address, referrerTwo.address, referrerThree.address],
            [ether(.3333), ether(.3333), ether(.3334)],
            ethers.encodeBytes32String("test")
          );

          await jackpot.connect(lpOne.wallet).initiateWithdraw(usdc(500000));

          if (runJackpot) {
            await time.increase(drawingDurationInSeconds);
            const drawingState = await jackpot.getDrawingState(1);
            await jackpot.runJackpot({ value: entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7)) });

            const winningNumbers = [[BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], [BigInt(6)]];
            await entropyProvider.randomnessCallback(winningNumbers);
          }

          subjectCaller = lpOne;
        });

        async function subject(): Promise<any> {
          return await jackpot.connect(subjectCaller.wallet).finalizeWithdraw();
        }

        it("should update LP state correctly", async () => {
          await subject();
          
          const actualLpState = await jackpotLPManager.getLpInfo(lpOne.address);

          expect(actualLpState.lastDeposit.amount).to.be.equal(0);
          expect(actualLpState.lastDeposit.drawingId).to.be.equal(0);
          expect(actualLpState.pendingWithdrawal.amountInShares).to.be.equal(0);
          expect(actualLpState.pendingWithdrawal.drawingId).to.be.equal(0);
          expect(actualLpState.consolidatedShares).to.be.equal(usdc(1500000));
          expect(actualLpState.claimableWithdrawals).to.be.equal(0);
        });

        it("should transfer the correct amount to the caller", async () => {
          const actualLpState: LP = await jackpotLPManager.getLpInfo(lpOne.address);
          const preLpBalance = await usdcMock.balanceOf(lpOne.address);
          const preContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());
          
          await subject();
          
          const drawingAccumulator = await jackpotLPManager.drawingAccumulator(1);

          const expectedWithdrawalAmount = (actualLpState.pendingWithdrawal.amountInShares * drawingAccumulator) / PRECISE_UNIT;
          const postLpBalance = await usdcMock.balanceOf(lpOne.address);
          const postContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());

          expect(postLpBalance).to.be.equal(preLpBalance + expectedWithdrawalAmount);
          expect(postContractBalance).to.be.equal(preContractBalance - expectedWithdrawalAmount);
        });

        it("should emit the correct LpWithdrawFinalized event", async () => {
          const actualLpState: LP = await jackpotLPManager.getLpInfo(lpOne.address);
          const drawingAccumulator = await jackpotLPManager.drawingAccumulator(1);
          const expectedWithdrawalAmount = (actualLpState.pendingWithdrawal.amountInShares * drawingAccumulator) / PRECISE_UNIT;

          await expect(subject()).to.emit(jackpotLPManager, "LpWithdrawFinalized").withArgs(
            lpOne.address,
            2,
            expectedWithdrawalAmount
          );
        });

        describe("when there are claimable withdrawals but an ineligible pending withdrawal", async () => {
          beforeEach(async () => {
            await jackpot.connect(lpOne.wallet).initiateWithdraw(usdc(500000));
          });
          
          it("should update the claimableWithdrawals", async () => {
            const preLpState: LP = await jackpotLPManager.getLpInfo(lpOne.address);
            expect(preLpState.claimableWithdrawals).to.greaterThan(0);

            await subject();

            const actualLpState: LP = await jackpotLPManager.getLpInfo(lpOne.address);
            expect(actualLpState.claimableWithdrawals).to.be.equal(0);
          });

          it("should transfer the correct amount to the caller", async () => {
            const actualLpState: LP = await jackpotLPManager.getLpInfo(lpOne.address);
            const preLpBalance = await usdcMock.balanceOf(lpOne.address);
            const preContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());
            
            await subject();
  
            const expectedWithdrawalAmount = actualLpState.claimableWithdrawals;
            const postLpBalance = await usdcMock.balanceOf(lpOne.address);
            const postContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());
  
            expect(postLpBalance).to.be.equal(preLpBalance + expectedWithdrawalAmount);
            expect(postContractBalance).to.be.equal(preContractBalance - expectedWithdrawalAmount);
          });

          it("should emit the correct LpWithdrawFinalized event", async () => {
            const actualLpState: LP = await jackpotLPManager.getLpInfo(lpOne.address);
            const expectedWithdrawalAmount = actualLpState.claimableWithdrawals;
  
            await expect(subject()).to.emit(jackpotLPManager, "LpWithdrawFinalized").withArgs(
              lpOne.address,
              2,
              expectedWithdrawalAmount
            );
          });
        });

        describe("when there are claimable withdrawals and an eligible pending withdrawal", async () => {
          beforeEach(async () => {
            await jackpot.connect(lpOne.wallet).initiateWithdraw(usdc(500000));

            await time.increase(drawingDurationInSeconds);
            const drawingState = await jackpot.getDrawingState(1);
            await jackpot.runJackpot({ value: entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7)) });
  
            const winningNumbers = [[BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], [BigInt(6)]];
            await entropyProvider.randomnessCallback(winningNumbers);
          });
          
          it("should update the claimableWithdrawals", async () => {
            const preLpState: LP = await jackpotLPManager.getLpInfo(lpOne.address);
            expect(preLpState.claimableWithdrawals).to.greaterThan(0);

            await subject();

            const actualLpState: LP = await jackpotLPManager.getLpInfo(lpOne.address);
            expect(actualLpState.claimableWithdrawals).to.be.equal(0);
          });

          it("should update the pendingWithdrawal", async () => {
            const preLpState: LP = await jackpotLPManager.getLpInfo(lpOne.address);
            expect(preLpState.pendingWithdrawal.amountInShares).to.greaterThan(0);

            await subject();

            const actualLpState: LP = await jackpotLPManager.getLpInfo(lpOne.address);
            expect(actualLpState.pendingWithdrawal.amountInShares).to.be.equal(0);
            expect(actualLpState.pendingWithdrawal.drawingId).to.be.equal(0);
          });

          it("should transfer the correct amount to the caller", async () => {
            const actualLpState: LP = await jackpotLPManager.getLpInfo(lpOne.address);
            const preLpBalance = await usdcMock.balanceOf(lpOne.address);
            const preContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());
            
            await subject();
            
            const drawingAccumulator = await jackpotLPManager.drawingAccumulator(1);
  
            const expectedWithdrawalAmount = ((actualLpState.pendingWithdrawal.amountInShares * drawingAccumulator) / PRECISE_UNIT)
                + actualLpState.claimableWithdrawals;
            const postLpBalance = await usdcMock.balanceOf(lpOne.address);
            const postContractBalance = await usdcMock.balanceOf(await jackpot.getAddress());
  
            expect(postLpBalance).to.be.equal(preLpBalance + expectedWithdrawalAmount);
            expect(postContractBalance).to.be.equal(preContractBalance - expectedWithdrawalAmount);
          });

          it("should emit the correct LpWithdrawFinalized event", async () => {
            const actualLpState: LP = await jackpotLPManager.getLpInfo(lpOne.address);
            const drawingAccumulator = await jackpotLPManager.drawingAccumulator(1);
            const expectedWithdrawalAmount = (actualLpState.pendingWithdrawal.amountInShares * drawingAccumulator) / PRECISE_UNIT
                + actualLpState.claimableWithdrawals;
  
            await expect(subject()).to.emit(jackpotLPManager, "LpWithdrawFinalized").withArgs(
              lpOne.address,
              3,
              expectedWithdrawalAmount
            );
          });
        });

        describe("when there is only an ineligible pending withdrawal", async () => {
          before(async () => {
            runJackpot = false;
          });

          after(async () => {
            runJackpot = true;
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "NothingToWithdraw");
          });
        });

        describe("when the caller has no pending or claimable withdrawals", async () => {
          beforeEach(async () => {
            subjectCaller = buyerOne;
          });
          
          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "NothingToWithdraw");
          });
        });

        describe("when emergency mode is enabled", async () => {
          beforeEach(async () => {
            await jackpot.connect(owner.wallet).enableEmergencyMode();
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "EmergencyEnabled");
          });
        });

        describe("when the reentrancy protection is violated", async () => {
          beforeEach(async () => {
            await usdcMock.setCallbackTarget(await jackpot.getAddress());
            const callbackData = jackpot.interface.encodeFunctionData(
              "finalizeWithdraw",
              []
            );
            await usdcMock.setCallbackData(callbackData)
            await usdcMock.enableCallback();
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "ReentrancyGuardReentrantCall");
          });
        });
      });

      describe("#transferFrom", async () => {
        let subjectFrom: Account;
        let subjectTo: Account;
        let subjectTicketId: bigint;
        let subjectCaller: Account;

        let ticketInfo: Ticket[];

        beforeEach(async () => {
          await usdcMock.connect(buyerOne.wallet).approve(jackpot.getAddress(), usdc(5));
          
          ticketInfo = [
            {
              normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
              bonusball: BigInt(6)
            } as Ticket,
            {
              normals: [BigInt(2), BigInt(3), BigInt(4), BigInt(5), BigInt(6)],
              bonusball: BigInt(3)
            } as Ticket,
          ]
          const ticketIds = await jackpot.connect(buyerOne.wallet).buyTickets.staticCall(
            ticketInfo,
            buyerOne.address,
            [referrerOne.address, referrerTwo.address, referrerThree.address],
            [ether(.3333), ether(.3333), ether(.3334)],
            ethers.encodeBytes32String("test")
          );

          await jackpot.connect(buyerOne.wallet).buyTickets(
            ticketInfo,
            buyerOne.address,
            [referrerOne.address, referrerTwo.address, referrerThree.address],
            [ether(.3333), ether(.3333), ether(.3334)],
            ethers.encodeBytes32String("test")
          );

          subjectFrom = buyerOne;
          subjectTo = buyerTwo;
          subjectTicketId = ticketIds[0];
          subjectCaller = buyerOne;
        });

        async function subject(): Promise<any> {
          return await jackpotNFT.connect(subjectCaller.wallet).transferFrom(subjectFrom.address, subjectTo.address, subjectTicketId);
        }

        it("should transfer the ticket to the new owner", async () => {
          const preBalanceBuyerOne = await jackpotNFT.balanceOf(buyerOne.address);
          const preBalanceBuyerTwo = await jackpotNFT.balanceOf(buyerTwo.address);
          
          await subject();

          const newOwner = await jackpotNFT.ownerOf(subjectTicketId);
          const postBalanceBuyerOne = await jackpotNFT.balanceOf(buyerOne.address);
          const postBalanceBuyerTwo = await jackpotNFT.balanceOf(buyerTwo.address);

          expect(newOwner).to.be.equal(subjectTo.address);
          expect(postBalanceBuyerOne).to.be.equal(preBalanceBuyerOne - BigInt(1));
          expect(postBalanceBuyerTwo).to.be.equal(preBalanceBuyerTwo + BigInt(1));
        });
        
        it("should update the user tickets for the new owner", async () => {
          await subject();

          const userTickets: ExtendedTrackedTicket[] = await jackpotNFT.getUserTickets(subjectTo.address, 1);
          expect(userTickets.length).to.be.equal(1);
          expect(userTickets[0].ticket.packedTicket).to.be.equal(calculatePackedTicket(ticketInfo[0], BigInt(normalBallMax)));
          expect(userTickets[0].normals).to.deep.equal(ticketInfo[0].normals);
          expect(userTickets[0].bonusball).to.equal(ticketInfo[0].bonusball);
        });

        it("should update the user tickets for the old owner", async () => {
          await subject();

          const userTickets: ExtendedTrackedTicket[] = await jackpotNFT.getUserTickets(subjectFrom.address, 1);
          expect(userTickets.length).to.be.equal(1);
          expect(userTickets[0].ticket.packedTicket).to.be.equal(calculatePackedTicket(ticketInfo[1], BigInt(normalBallMax)));
          expect(userTickets[0].normals).to.deep.equal(ticketInfo[1].normals);
          expect(userTickets[0].bonusball).to.equal(ticketInfo[1].bonusball);
        });
      });

      describe("#getUnpackedTicket", async () => {
        let subjectDrawingId: bigint;
        let subjectPackedTicket: bigint;

        let ticketInfo: Ticket;

        beforeEach(async () => {
          ticketInfo = {
              normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
              bonusball: BigInt(6)
            } as Ticket,

          subjectDrawingId = BigInt(1);
          subjectPackedTicket = calculatePackedTicket(ticketInfo, normalBallMax);
        });

        async function subject(): Promise<any> {
          return await jackpot.getUnpackedTicket(1, subjectPackedTicket);
        }

        it("should return the unpacked ticket", async () => {
          const [unpackedNormals, unpackedBonusball] = await subject();
          expect(unpackedNormals).to.deep.equal(ticketInfo.normals);
          expect(unpackedBonusball).to.equal(ticketInfo.bonusball);
        });
      });

      describe("#emergencyWithdrawLP", async () => {
        let subjectCaller: Account;

        beforeEach(async () => {
          subjectCaller = lpOne; // LP user calling emergency withdraw
          
          // Setup some LP position for testing (lpOne already has USDC from initialization)
          await usdcMock.connect(lpOne.wallet).approve(await jackpot.getAddress(), usdc(10000));
          await jackpot.connect(lpOne.wallet).lpDeposit(usdc(1000));
        });

        async function subject(): Promise<any> {
          return await jackpot.connect(subjectCaller.wallet).emergencyWithdrawLP();
        }

        describe("when emergency mode is not engaged", async () => {
          it("should revert with EmergencyModeNotEngaged", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "EmergencyModeNotEngaged");
          });
        });

        describe("when emergency mode is engaged", async () => {
          beforeEach(async () => {
            await jackpot.connect(owner.wallet).enableEmergencyMode();
          });

          it("should allow emergency withdrawal", async () => {
            const preUSDCBalance = await usdcMock.balanceOf(lpOne.address);
            
            await subject();
            
            const postUSDCBalance = await usdcMock.balanceOf(lpOne.address);
            // 2M original deposit + 1k from this test
            expect(postUSDCBalance).to.equal(preUSDCBalance + usdc(2001000));
          });

          it("should clear LP position after emergency withdrawal", async () => {
            await subject();
            
            const lpInfo = await jackpotLPManager.getLpInfo(lpOne.address);
            expect(lpInfo.consolidatedShares).to.equal(0n);
            expect(lpInfo.lastDeposit.amount).to.equal(0n);
            expect(lpInfo.lastDeposit.drawingId).to.equal(0n);
            expect(lpInfo.pendingWithdrawal.amountInShares).to.equal(0n);
            expect(lpInfo.pendingWithdrawal.drawingId).to.equal(0n);
            expect(lpInfo.claimableWithdrawals).to.equal(0n);
          });
        });

        describe("when LP has complex positions", async () => {
          beforeEach(async () => {
            // Create more complex LP state
            await jackpot.connect(lpOne.wallet).lpDeposit(usdc(2000)); // Additional deposit
            await jackpot.connect(lpOne.wallet).initiateWithdraw(usdc(500)); // Initiate some withdrawal
            await jackpot.connect(owner.wallet).enableEmergencyMode();
          });

          it("should handle complex LP positions correctly", async () => {
            const preUSDCBalance = await usdcMock.balanceOf(lpOne.address);

            await subject();
            
            const postUSDCBalance = await usdcMock.balanceOf(lpOne.address);
            // 2M original deposit + 1k from this test + 2k from beforeEach
            expect(postUSDCBalance).to.equal(preUSDCBalance + usdc(2003000));
            
            // Verify all positions are cleared
            const lpInfo = await jackpotLPManager.getLpInfo(lpOne.address);
            expect(lpInfo.consolidatedShares).to.equal(0n);
            expect(lpInfo.lastDeposit.amount).to.equal(0n);
            expect(lpInfo.claimableWithdrawals).to.equal(0n);
          });
        });

        describe("when LP has no positions", async () => {
          beforeEach(async () => {
            // Use a different user with no LP positions
            subjectCaller = user;
            await jackpot.connect(owner.wallet).enableEmergencyMode();
          });

          it("should handle empty LP positions gracefully", async () => {
            const preUSDCBalance = await usdcMock.balanceOf(user.address);
            
            await subject();
            
            const postUSDCBalance = await usdcMock.balanceOf(user.address);
            expect(postUSDCBalance).to.equal(preUSDCBalance); // No change for empty position
          });
        });

        describe("when the reentrancy protection is violated", async () => {
          beforeEach(async () => {
            await jackpot.connect(owner.wallet).enableEmergencyMode(); 
            await usdcMock.setCallbackTarget(await jackpot.getAddress());
            const callbackData = jackpot.interface.encodeFunctionData(
              "emergencyWithdrawLP",
              []
            );
            await usdcMock.setCallbackData(callbackData)
            await usdcMock.enableCallback();
          });

          it("should revert", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "ReentrancyGuardReentrantCall");
          });
        });
      });

      describe("#emergencyRefundTickets", async () => {
        let subjectUserTicketIds: bigint[];
        let subjectCaller: Account;

        beforeEach(async () => {
          const batchOne = [
            {
              normals: [BigInt(2), BigInt(4), BigInt(6), BigInt(7), BigInt(11)],
              bonusball: BigInt(3)
            } as Ticket,
          ];
          const batchTwo = [
            {
              normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
              bonusball: BigInt(1)
            } as Ticket
          ];

          await usdcMock.connect(buyerOne.wallet).approve(jackpot.getAddress(), usdc(10000));
          
          const source = ethers.encodeBytes32String("test");
          const ticketIdsOne = await jackpot.connect(buyerOne.wallet).buyTickets.staticCall(batchOne, buyerOne.address, [], [], source);
          await jackpot.connect(buyerOne.wallet).buyTickets(batchOne, buyerOne.address, [], [], source);
          const ticketIdsTwo = await jackpot.connect(buyerOne.wallet).buyTickets.staticCall(batchTwo, buyerOne.address, [referrerOne.address], [PRECISE_UNIT], source);
          await jackpot.connect(buyerOne.wallet).buyTickets(batchTwo, buyerOne.address, [referrerOne.address], [PRECISE_UNIT], source);

          subjectUserTicketIds = [...ticketIdsOne, ...ticketIdsTwo];
          subjectCaller = buyerOne; // User calling emergency refund
        });

        async function subject(): Promise<any> {
          return await jackpot.connect(subjectCaller.wallet).emergencyRefundTickets(subjectUserTicketIds);
        }

        describe("when emergency mode is not engaged", async () => {
          it("should revert with EmergencyModeNotEngaged", async () => {
            await expect(subject()).to.be.revertedWithCustomError(jackpot, "EmergencyModeNotEngaged");
          });
        });

        describe("when emergency mode is engaged", async () => {
          beforeEach(async () => {
            await jackpot.connect(owner.wallet).enableEmergencyMode();
          });

          it("should allow emergency refund", async () => {
            const preUSDCBalance = await usdcMock.balanceOf(buyerOne.address);
            
            await subject();
            
            const postUSDCBalance = await usdcMock.balanceOf(buyerOne.address);
            const ticketPrice = await jackpot.ticketPrice();
            const refundAmount = (ticketPrice * (PRECISE_UNIT - referralFee) / PRECISE_UNIT) + ticketPrice;
            // 2M original deposit + 1k from this test
            expect(postUSDCBalance).to.equal(preUSDCBalance + refundAmount);
          });

          it("should burn the tickets", async () => {
            await subject();
            
            await expect(jackpotNFT.ownerOf(subjectUserTicketIds[0])).to.revertedWithCustomError(jackpotNFT, "TokenDoesNotExist");
            await expect(jackpotNFT.ownerOf(subjectUserTicketIds[1])).to.revertedWithCustomError(jackpotNFT, "TokenDoesNotExist");
          });

          it("should emit the correct TicketRefunded event", async () => {
            const tx = await subject();
            await expect(tx).to.emit(jackpot, "TicketRefunded").withArgs(subjectUserTicketIds[0]);
            await expect(tx).to.emit(jackpot, "TicketRefunded").withArgs(subjectUserTicketIds[1]);
          });

          describe("when no tickets are provided", async () => {
            beforeEach(async () => {
              subjectUserTicketIds = [];
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "NoTicketsProvided");
            });
          });

          describe("when the caller does not own all the tickets", async () => {
            beforeEach(async () => {
              subjectCaller = buyerTwo;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "NotTicketOwner");
            });
          });

          describe("when the ticket is not from the current drawing", async () => {
            beforeEach(async () => {
              subjectUserTicketIds = [subjectUserTicketIds[0]+1n];
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "TicketNotEligibleForRefund");
            });
          });

          describe("when the reentrancy protection is violated", async () => {
            beforeEach(async () => {
              await usdcMock.setCallbackTarget(await jackpot.getAddress());
              const callbackData = jackpot.interface.encodeFunctionData(
                "emergencyRefundTickets",
                [subjectUserTicketIds]
              );
              await usdcMock.setCallbackData(callbackData)
              await usdcMock.enableCallback();
            });
  
            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "ReentrancyGuardReentrantCall");
            });
          });
        });
      });

      describe("#getTicketTierIds", async () => {
        let subjectTicketIds: bigint[];
        let subjectCaller: Account;

        let buyerOneTicketInfo: Ticket[];
        let buyerOneTicketIds: bigint[];

        let winningNumbers: bigint[][];

        beforeEach(async () => {
          await usdcMock.connect(buyerOne.wallet).approve(jackpot.getAddress(), usdc(6));

          buyerOneTicketInfo = [
            {
              normals: [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)],
              bonusball: BigInt(6)
            } as Ticket,
            {
              normals: [BigInt(6), BigInt(7), BigInt(8), BigInt(9), BigInt(10)],
              bonusball: BigInt(3)
            } as Ticket,
            {
              normals: [BigInt(1), BigInt(2), BigInt(5), BigInt(7), BigInt(9)],
              bonusball: BigInt(6)
            } as Ticket,
          ];

          // buyer one
          buyerOneTicketIds = await jackpot.connect(buyerOne.wallet).buyTickets.staticCall(
            buyerOneTicketInfo,
            buyerOne.address,
            [referrerOne.address, referrerTwo.address, referrerThree.address],
            [ether(.3333), ether(.3333), ether(.3334)],
            ethers.encodeBytes32String("test")
          );

          await jackpot.connect(buyerOne.wallet).buyTickets(
            buyerOneTicketInfo,
            buyerOne.address,
            [referrerOne.address, referrerTwo.address, referrerThree.address],
            [ether(.3333), ether(.3333), ether(.3334)],
            ethers.encodeBytes32String("test")
          );

          await time.increase(drawingDurationInSeconds);
          const drawingState = await jackpot.getDrawingState(1);
          await jackpot.runJackpot({ value: entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * drawingState.bonusballMax) * BigInt(1e7)) });

          winningNumbers = [[BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)], [BigInt(6)]];
          await entropyProvider.randomnessCallback(winningNumbers);

          subjectTicketIds = [...buyerOneTicketIds];
          subjectCaller = buyerOne;
        });

        async function subject(): Promise<any> {
          return await jackpot.getTicketTierIds(subjectTicketIds);
        }

        it("should return the correct tier ids", async () => {
          const tierIds = await subject();

          expect(tierIds).to.deep.equal([BigInt(11), BigInt(0), BigInt(7)]);
        });
      });

      describe("#getEntropyCallbackFee", async () => {
        async function subject(): Promise<any> {
          return await jackpot.getEntropyCallbackFee();
        }

        it("should return the correct entropy callback fee", async () => {
          const fee = await subject();
          const bonusballMax = (await jackpot.getDrawingState(1)).bonusballMax;
          expect(fee).to.equal(entropyFee + ((entropyBaseGasLimit + entropyVariableGasLimit * bonusballMax) * BigInt(1e7)));
        });
      });

      describe("Admin Functions", async () => {
        describe("#lockJackpot", async () => {
          let subjectCaller: Account;

          beforeEach(async () => {
            subjectCaller = owner;
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).lockJackpot();
          }

          it("should lock the current drawing", async () => {
            const preState = await jackpot.getDrawingState(1);
            expect(preState.jackpotLock).to.be.false;

            await subject();

            const postState = await jackpot.getDrawingState(1);
            expect(postState.jackpotLock).to.be.true;
          });

          it("should emit JackpotLocked event", async () => {
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "JackpotLocked")
              .withArgs(currentDrawingId);
          });

          describe("when the jackpot is already locked", async () => {
            beforeEach(async () => {
              await subject();
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "JackpotLocked");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#unlockJackpot", async () => {
          let subjectCaller: Account;

          beforeEach(async () => {
            await jackpot.connect(owner.wallet).lockJackpot();
            subjectCaller = owner;
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).unlockJackpot();
          }

          it("should unlock the current drawing", async () => {
            const preState = await jackpot.getDrawingState(1);
            expect(preState.jackpotLock).to.be.true;

            await subject();

            const postState = await jackpot.getDrawingState(1);
            expect(postState.jackpotLock).to.be.false;
          });

          it("should emit JackpotUnlocked event", async () => {
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "JackpotUnlocked")
              .withArgs(currentDrawingId);
          });

          describe("when the jackpot is not locked", async () => {
            beforeEach(async () => {
              await subject();
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "JackpotNotLocked");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#enableTicketPurchases", async () => {
          let subjectCaller: Account;

          beforeEach(async () => {
            await jackpot.connect(owner.wallet).disableTicketPurchases();
            subjectCaller = owner;
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).enableTicketPurchases();
          }

          it("should enable ticket purchases", async () => {
            const preState = await jackpot.allowTicketPurchases();
            expect(preState).to.be.false;

            await subject();

            const postState = await jackpot.allowTicketPurchases();
            expect(postState).to.be.true;
          });

          it("should emit TicketPurchasesEnabled event", async () => {
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "TicketPurchasesEnabled")
              .withArgs(currentDrawingId);
          });

          describe("when ticket purchases are already enabled", async () => {
            beforeEach(async () => {
              await subject();
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "TicketPurchasesAlreadyEnabled");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#disableTicketPurchases", async () => {
          let subjectCaller: Account;

          beforeEach(async () => {
            subjectCaller = owner;
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).disableTicketPurchases();
          }

          it("should disable ticket purchases", async () => {
            const preState = await jackpot.allowTicketPurchases();
            expect(preState).to.be.true;

            await subject();

            const postState = await jackpot.allowTicketPurchases();
            expect(postState).to.be.false;
          });

          it("should emit TicketPurchasesDisabled event", async () => {
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "TicketPurchasesDisabled")
              .withArgs(currentDrawingId);
          });

          describe("when ticket purchases are already disabled", async () => {
            beforeEach(async () => {
              await subject();
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "TicketPurchasesAlreadyDisabled");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setNormalBallMax", async () => {
          let subjectCaller: Account;
          let subjectNormalBallMax: bigint;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectNormalBallMax = BigInt(70); // Different from default (30)
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setNormalBallMax(subjectNormalBallMax);
          }

          it("should update the normalBallMax", async () => {
            const preNormalBallMax = await jackpot.normalBallMax();
            expect(preNormalBallMax).to.equal(BigInt(30));

            await subject();

            const postNormalBallMax = await jackpot.normalBallMax();
            expect(postNormalBallMax).to.equal(subjectNormalBallMax);
          });

          it("should call setLPPoolCap on the LP manager", async () => {
            // The function should execute without reverting, indicating LP pool cap was updated
            const preLPPoolCap = await jackpotLPManager.lpPoolCap();
            
            await expect(subject()).to.not.be.reverted;
            
            // Verify the normalBallMax was actually updated
            const postLpPoolCap = await jackpotLPManager.lpPoolCap();

            expect(postLpPoolCap).to.not.equal(preLPPoolCap);
          });

          it("should emit NormalBallMaxUpdated event", async () => {
            const preNormalBallMax = await jackpot.normalBallMax();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "NormalBallMaxUpdated")
              .withArgs(currentDrawingId, preNormalBallMax, subjectNormalBallMax);
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setProtocolFeeThreshold", async () => {
          let subjectCaller: Account;
          let subjectProtocolFeeThreshold: bigint;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectProtocolFeeThreshold = usdc(500); // Different from default
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setProtocolFeeThreshold(subjectProtocolFeeThreshold);
          }

          it("should update the protocolFeeThreshold", async () => {
            await subject();
            
            const postThreshold = await jackpot.protocolFeeThreshold();
            expect(postThreshold).to.equal(subjectProtocolFeeThreshold);
          });

          it("should emit ProtocolFeeThresholdUpdated event", async () => {
            const preThreshold = await jackpot.protocolFeeThreshold();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "ProtocolFeeThresholdUpdated")
              .withArgs(currentDrawingId, preThreshold, subjectProtocolFeeThreshold);
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setProtocolFee", async () => {
          let subjectCaller: Account;
          let subjectProtocolFee: bigint;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectProtocolFee = PRECISE_UNIT * BigInt(15) / BigInt(100); // 15% instead of default 10%
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setProtocolFee(subjectProtocolFee);
          }

          it("should update the protocolFee", async () => {
            const preFee = await jackpot.protocolFee();
            
            await subject();
            
            const postFee = await jackpot.protocolFee();
            expect(postFee).to.equal(subjectProtocolFee);
          });

          it("should emit ProtocolFeeUpdated event", async () => {
            const preFee = await jackpot.protocolFee();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "ProtocolFeeUpdated")
              .withArgs(currentDrawingId, preFee, subjectProtocolFee);
          });

          describe("when the protocolFee is > MAX_PROTOCOL_FEE", async () => {
            beforeEach(async () => {
              subjectProtocolFee = ether(.26); // 26%
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidProtocolFee");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setGovernancePoolCap", async () => {
          let subjectCaller: Account;
          let subjectGovernancePoolCap: bigint;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectGovernancePoolCap = usdc(10000000);
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setGovernancePoolCap(subjectGovernancePoolCap);
          }

          it("should update the governancePoolCap", async () => {
            await subject();
            
            const postGovernancePoolCap = await jackpot.governancePoolCap();
            expect(postGovernancePoolCap).to.equal(subjectGovernancePoolCap);
          });

          it("should call setLPPoolCap on the LP manager", async () => {
            await subject();
            
            const postGovernancePoolCap = await jackpotLPManager.lpPoolCap();
            expect(postGovernancePoolCap).to.equal(subjectGovernancePoolCap);
          });

          it("should emit GovernancePoolCapUpdated event", async () => {
            const preGovernancePoolCap = await jackpot.governancePoolCap();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "GovernancePoolCapUpdated")
              .withArgs(currentDrawingId, preGovernancePoolCap, subjectGovernancePoolCap);
          });

          describe("when the governancePoolCap is zero", async () => {
            beforeEach(async () => {
              subjectGovernancePoolCap = 0n;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidGovernancePoolCap");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setDrawingDurationInSeconds", async () => {
          let subjectCaller: Account;
          let subjectDrawingDurationInSeconds: bigint;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectDrawingDurationInSeconds = BigInt(7200); // 2 hours
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setDrawingDurationInSeconds(subjectDrawingDurationInSeconds);
          }

          it("should update the drawingDurationInSeconds", async () => {
            const preDuration = await jackpot.drawingDurationInSeconds();
            
            await subject();
            
            const postDuration = await jackpot.drawingDurationInSeconds();
            expect(postDuration).to.equal(subjectDrawingDurationInSeconds);
            expect(postDuration).to.not.equal(preDuration);
          });

          it("should emit DrawingDurationUpdated event", async () => {
            const preDuration = await jackpot.drawingDurationInSeconds();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "DrawingDurationUpdated")
              .withArgs(currentDrawingId, preDuration, subjectDrawingDurationInSeconds);
          });

          describe("when the duration is zero", async () => {
            beforeEach(async () => {
              subjectDrawingDurationInSeconds = 0n;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidDrawingDuration");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setBonusballMin", async () => {
          let subjectCaller: Account;
          let subjectBonusballMin: bigint;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectBonusballMin = 10n; // Different from default (5)
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setBonusballMin(subjectBonusballMin);
          }

          it("should update the bonusballMin", async () => {
            const preBonusballMin = await jackpot.bonusballMin();
            
            await subject();
            
            const postBonusballMin = await jackpot.bonusballMin();
            expect(postBonusballMin).to.equal(subjectBonusballMin);
            expect(postBonusballMin).to.not.equal(preBonusballMin);
          });

          it("should emit BonusballMinUpdated event", async () => {
            const preBonusballMin = await jackpot.bonusballMin();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "BonusballMinUpdated")
              .withArgs(currentDrawingId, preBonusballMin, subjectBonusballMin);
          });

          describe("when the bonusballMin is zero", async () => {
            beforeEach(async () => {
              subjectBonusballMin = 0n;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidBonusballMin");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setLpEdgeTarget", async () => {
          let subjectCaller: Account;
          let subjectLpEdgeTarget: bigint;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectLpEdgeTarget = ether(0.15); // Different from default (0.3)
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setLpEdgeTarget(subjectLpEdgeTarget);
          }

          it("should update the lpEdgeTarget", async () => {
            const preLpEdgeTarget = await jackpot.lpEdgeTarget();
            
            await subject();
            
            const postLpEdgeTarget = await jackpot.lpEdgeTarget();
            expect(postLpEdgeTarget).to.equal(subjectLpEdgeTarget);
            expect(postLpEdgeTarget).to.not.equal(preLpEdgeTarget);
          });

          it("should call setLPPoolCap on the LP manager", async () => {
            // The function should execute without reverting, indicating LP pool cap was updated
            const preLPPoolCap = await jackpotLPManager.lpPoolCap();
            
            await expect(subject()).to.not.be.reverted;
            
            // Verify the normalBallMax was actually updated
            const postLpPoolCap = await jackpotLPManager.lpPoolCap();

            expect(postLpPoolCap).to.not.equal(preLPPoolCap);
          });

          it("should emit LpEdgeTargetUpdated event", async () => {
            const preLpEdgeTarget = await jackpot.lpEdgeTarget();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "LpEdgeTargetUpdated")
              .withArgs(currentDrawingId, preLpEdgeTarget, subjectLpEdgeTarget);
          });

          describe("when the lpEdgeTarget is zero", async () => {
            beforeEach(async () => {
              subjectLpEdgeTarget = 0n;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidLpEdgeTarget");
            });
          });

          describe("when the lpEdgeTarget is >= PRECISE_UNIT", async () => {
            beforeEach(async () => {
              subjectLpEdgeTarget = ether(1); // 100%
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidLpEdgeTarget");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setReserveRatio", async () => {
          let subjectCaller: Account;
          let subjectReserveRatio: bigint;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectReserveRatio = ether(0.1); // Different from default (0.2)
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setReserveRatio(subjectReserveRatio);
          }

          it("should update the reserveRatio", async () => {
            const preReserveRatio = await jackpot.reserveRatio();
            
            await subject();
            
            const postReserveRatio = await jackpot.reserveRatio();
            expect(postReserveRatio).to.equal(subjectReserveRatio);
            expect(postReserveRatio).to.not.equal(preReserveRatio);
          });

          it("should call setLPPoolCap on the LP manager", async () => {
            // The function should execute without reverting, indicating LP pool cap was updated
            const preLPPoolCap = await jackpotLPManager.lpPoolCap();
            
            await expect(subject()).to.not.be.reverted;
            
            // Verify the normalBallMax was actually updated
            const postLpPoolCap = await jackpotLPManager.lpPoolCap();

            expect(postLpPoolCap).to.not.equal(preLPPoolCap);
          });

          it("should emit ReserveRatioUpdated event", async () => {
            const preReserveRatio = await jackpot.reserveRatio();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "ReserveRatioUpdated")
              .withArgs(currentDrawingId, preReserveRatio, subjectReserveRatio);
          });

          describe("when the reserveRatio is zero", async () => {
            beforeEach(async () => {
              subjectReserveRatio = 0n;
            });

            it("should allow zero reserve ratio", async () => {
              await subject();
              
              const postReserveRatio = await jackpot.reserveRatio();
              expect(postReserveRatio).to.equal(0n);
            });
          });

          describe("when the reserveRatio is >= PRECISE_UNIT", async () => {
            beforeEach(async () => {
              subjectReserveRatio = ether(1); // 100%
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidReserveRatio");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setReferralFee", async () => {
          let subjectCaller: Account;
          let subjectReferralFee: bigint;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectReferralFee = ether(0.05); // Different from default (0.065)
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setReferralFee(subjectReferralFee);
          }

          it("should update the referralFee", async () => {
            const preReferralFee = await jackpot.referralFee();
            
            await subject();
            
            const postReferralFee = await jackpot.referralFee();
            expect(postReferralFee).to.equal(subjectReferralFee);
            expect(postReferralFee).to.not.equal(preReferralFee);
          });

          it("should emit ReferralFeeUpdated event", async () => {
            const preReferralFee = await jackpot.referralFee();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "ReferralFeeUpdated")
              .withArgs(currentDrawingId, preReferralFee, subjectReferralFee);
          });

          describe("when the referralFee is zero", async () => {
            beforeEach(async () => {
              subjectReferralFee = 0n;
            });

            it("should allow zero referral fee", async () => {
              await subject();
              
              const postReferralFee = await jackpot.referralFee();
              expect(postReferralFee).to.equal(0n);
            });
          });

          describe("when the referralFee is > PRECISE_UNIT", async () => {
            beforeEach(async () => {
              subjectReferralFee = ether(1.1); // 110%
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidReferralFee");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setReferralWinShare", async () => {
          let subjectCaller: Account;
          let subjectReferralWinShare: bigint;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectReferralWinShare = ether(0.08); // Different from default (0.05)
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setReferralWinShare(subjectReferralWinShare);
          }

          it("should update the referralWinShare", async () => {
            const preReferralWinShare = await jackpot.referralWinShare();
            
            await subject();
            
            const postReferralWinShare = await jackpot.referralWinShare();
            expect(postReferralWinShare).to.equal(subjectReferralWinShare);
            expect(postReferralWinShare).to.not.equal(preReferralWinShare);
          });

          it("should emit ReferralWinShareUpdated event", async () => {
            const preReferralWinShare = await jackpot.referralWinShare();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "ReferralWinShareUpdated")
              .withArgs(currentDrawingId, preReferralWinShare, subjectReferralWinShare);
          });

          describe("when the referralWinShare is zero", async () => {
            beforeEach(async () => {
              subjectReferralWinShare = 0n;
            });

            it("should allow zero referral win share", async () => {
              await subject();
              
              const postReferralWinShare = await jackpot.referralWinShare();
              expect(postReferralWinShare).to.equal(0n);
            });
          });

          describe("when the referralWinShare is > PRECISE_UNIT", async () => {
            beforeEach(async () => {
              subjectReferralWinShare = ether(1.1); // 110%
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidReferralWinShare");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setProtocolFeeAddress", async () => {
          let subjectCaller: Account;
          let subjectProtocolFeeAddress: string;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectProtocolFeeAddress = user.address; // Different from default (owner)
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setProtocolFeeAddress(subjectProtocolFeeAddress);
          }

          it("should update the protocolFeeAddress", async () => {
            const preProtocolFeeAddress = await jackpot.protocolFeeAddress();
            
            await subject();
            
            const postProtocolFeeAddress = await jackpot.protocolFeeAddress();
            expect(postProtocolFeeAddress).to.equal(subjectProtocolFeeAddress);
            expect(postProtocolFeeAddress).to.not.equal(preProtocolFeeAddress);
          });

          it("should emit ProtocolFeeAddressUpdated event", async () => {
            const preProtocolFeeAddress = await jackpot.protocolFeeAddress();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "ProtocolFeeAddressUpdated")
              .withArgs(currentDrawingId, preProtocolFeeAddress, subjectProtocolFeeAddress);
          });

          describe("when the protocolFeeAddress is zero", async () => {
            beforeEach(async () => {
              subjectProtocolFeeAddress = ADDRESS_ZERO;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "ZeroAddress");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setTicketPrice", async () => {
          let subjectCaller: Account;
          let subjectTicketPrice: bigint;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectTicketPrice = usdc(2); // Different from default (usdc(1))
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setTicketPrice(subjectTicketPrice);
          }

          it("should update the ticketPrice", async () => {
            const preTicketPrice = await jackpot.ticketPrice();
            
            await subject();
            
            const postTicketPrice = await jackpot.ticketPrice();
            expect(postTicketPrice).to.equal(subjectTicketPrice);
            expect(postTicketPrice).to.not.equal(preTicketPrice);
          });

          it("should update the LP pool cap correctly", async () => {
            const preLPPoolCap = await jackpotLPManager.lpPoolCap();
            const normalBallMax = await jackpot.normalBallMax();
            const lpEdgeTarget = await jackpot.lpEdgeTarget();
            const reserveRatio = await jackpot.reserveRatio();
            
            await subject();
            
            // Calculate expected LP pool cap with new ticket price
            const expectedLPPoolCap = calculateLpPoolCap(normalBallMax, subjectTicketPrice, lpEdgeTarget, reserveRatio);
            
            const postLPPoolCap = await jackpotLPManager.lpPoolCap();
            expect(postLPPoolCap).to.equal(expectedLPPoolCap);
            expect(postLPPoolCap).to.be.greaterThan(preLPPoolCap);
          });

          it("should emit TicketPriceUpdated event", async () => {
            const preTicketPrice = await jackpot.ticketPrice();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "TicketPriceUpdated")
              .withArgs(currentDrawingId, preTicketPrice, subjectTicketPrice);
          });

          describe("when the ticketPrice is zero", async () => {
            beforeEach(async () => {
              subjectTicketPrice = 0n;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidTicketPrice");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setMaxReferrers", async () => {
          let subjectCaller: Account;
          let subjectMaxReferrers: bigint;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectMaxReferrers = 3n; // Different from default (5)
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setMaxReferrers(subjectMaxReferrers);
          }

          it("should update the maxReferrers", async () => {
            const preMaxReferrers = await jackpot.maxReferrers();
            
            await subject();
            
            const postMaxReferrers = await jackpot.maxReferrers();
            expect(postMaxReferrers).to.equal(subjectMaxReferrers);
            expect(postMaxReferrers).to.not.equal(preMaxReferrers);
          });

          it("should emit MaxReferrersUpdated event", async () => {
            const preMaxReferrers = await jackpot.maxReferrers();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "MaxReferrersUpdated")
              .withArgs(currentDrawingId, preMaxReferrers, subjectMaxReferrers);
          });

          describe("when the maxReferrers is zero", async () => {
            beforeEach(async () => {
              subjectMaxReferrers = 0n;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "InvalidMaxReferrers");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setPayoutCalculator", async () => {
          let subjectCaller: Account;
          let subjectPayoutCalculator: string;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectPayoutCalculator = user.address; // Different address for testing
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setPayoutCalculator(subjectPayoutCalculator);
          }

          it("should update the payoutCalculator", async () => {
            const prePayoutCalculator = await jackpot.payoutCalculator();
            
            await subject();
            
            const postPayoutCalculator = await jackpot.payoutCalculator();
            expect(postPayoutCalculator).to.equal(subjectPayoutCalculator);
            expect(postPayoutCalculator).to.not.equal(prePayoutCalculator);
          });

          it("should emit PayoutCalculatorUpdated event", async () => {
            const prePayoutCalculator = await jackpot.payoutCalculator();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "PayoutCalculatorUpdated")
              .withArgs(currentDrawingId, prePayoutCalculator, subjectPayoutCalculator);
          });

          describe("when the payoutCalculator is zero address", async () => {
            beforeEach(async () => {
              subjectPayoutCalculator = ADDRESS_ZERO;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "ZeroAddress");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setEntropy", async () => {
          let subjectCaller: Account;
          let subjectEntropy: string;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectEntropy = user.address; // Different address for testing
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setEntropy(subjectEntropy);
          }

          it("should update the entropy", async () => {
            const preEntropy = await jackpot.entropy();
            
            await subject();
            
            const postEntropy = await jackpot.entropy();
            expect(postEntropy).to.equal(subjectEntropy);
            expect(postEntropy).to.not.equal(preEntropy);
          });

          it("should emit EntropyUpdated event", async () => {
            const preEntropy = await jackpot.entropy();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "EntropyUpdated")
              .withArgs(currentDrawingId, preEntropy, subjectEntropy);
          });

          describe("when the entropy is zero address", async () => {
            beforeEach(async () => {
              subjectEntropy = ADDRESS_ZERO;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "ZeroAddress");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setEntropyBaseGasLimit", async () => {
          let subjectCaller: Account;
          let subjectEntropyBaseGasLimit: bigint;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectEntropyBaseGasLimit = 20000000n;
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setEntropyBaseGasLimit(subjectEntropyBaseGasLimit);
          }

          it("should update the entropyBaseGasLimit", async () => {
            const preEntropyBaseGasLimit = await jackpot.entropyBaseGasLimit();
            
            await subject();
            
            const postEntropyBaseGasLimit = await jackpot.entropyBaseGasLimit();
            expect(postEntropyBaseGasLimit).to.equal(subjectEntropyBaseGasLimit);
            expect(postEntropyBaseGasLimit).to.not.equal(preEntropyBaseGasLimit);
          });

          it("should emit EntropyBaseGasLimitUpdated event", async () => {
            const preEntropyBaseGasLimit = await jackpot.entropyBaseGasLimit();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "EntropyBaseGasLimitUpdated")
              .withArgs(currentDrawingId, preEntropyBaseGasLimit, subjectEntropyBaseGasLimit);
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#setEntropyVariableGasLimit", async () => {
          let subjectCaller: Account;
          let subjectEntropyVariableGasLimit: bigint;

          beforeEach(async () => {
            subjectCaller = owner;
            subjectEntropyVariableGasLimit = BigInt(600000);
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).setEntropyVariableGasLimit(subjectEntropyVariableGasLimit);
          }

          it("should update the entropyBaseGasLimit", async () => {
            const preEntropyVariableGasLimit = await jackpot.entropyVariableGasLimit();
            
            await subject();
            
            const postEntropyVariableGasLimit = await jackpot.entropyVariableGasLimit();
            expect(postEntropyVariableGasLimit).to.equal(subjectEntropyVariableGasLimit);
            expect(postEntropyVariableGasLimit).to.not.equal(preEntropyVariableGasLimit);
          });

          it("should emit EntropyVariableGasLimitUpdated event", async () => {
            const preEntropyVariableGasLimit = await jackpot.entropyVariableGasLimit();
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "EntropyVariableGasLimitUpdated")
              .withArgs(currentDrawingId, preEntropyVariableGasLimit, subjectEntropyVariableGasLimit);
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#enableEmergencyMode", async () => {
          let subjectCaller: Account;

          beforeEach(async () => {
            subjectCaller = owner;
          });

          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).enableEmergencyMode();
          }

          it("should enable emergency mode", async () => {
            const preState = await jackpot.emergencyMode();
            expect(preState).to.be.false;

            await subject();

            const postState = await jackpot.emergencyMode();
            expect(postState).to.be.true;
          });

          it("should emit EmergencyModeEnabled event", async () => {
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "EmergencyModeEnabled")
              .withArgs(currentDrawingId);
          });

          describe("when emergency mode is already enabled", async () => {
            beforeEach(async () => {
              await subject();
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "EmergencyModeAlreadyEnabled");
            });
          });

          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });

            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });

        describe("#disableEmergencyMode", async () => {
          let subjectCaller: Account;
  
          beforeEach(async () => {
            await jackpot.connect(owner.wallet).enableEmergencyMode();
            subjectCaller = owner;
          });
  
          async function subject(): Promise<any> {
            return await jackpot.connect(subjectCaller.wallet).disableEmergencyMode();
          }
  
          it("should disable emergency mode", async () => {
            const preState = await jackpot.emergencyMode();
            expect(preState).to.be.true;
  
            await subject();
  
            const postState = await jackpot.emergencyMode();
            expect(postState).to.be.false;
          });
  
          it("should emit EmergencyModeDisabled event", async () => {
            const currentDrawingId = await jackpot.currentDrawingId();
            
            await expect(subject())
              .to.emit(jackpot, "EmergencyModeDisabled")
              .withArgs(currentDrawingId);
          });
  
          describe("when emergency mode is already disabled", async () => {
            beforeEach(async () => {
              await subject();
            });
  
            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "EmergencyModeAlreadyDisabled");
            });
          });
  
          describe("when the caller is not the owner", async () => {
            beforeEach(async () => {
              subjectCaller = user;
            });
  
            it("should revert", async () => {
              await expect(subject()).to.be.revertedWithCustomError(jackpot, "OwnableUnauthorizedAccount");
            });
          });
        });
      });
    });
  });
});
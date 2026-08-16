import { ethers } from "hardhat";
import DeployHelper from "@utils/deploys";

import {
  getWaffleExpect,
  getAccounts
} from "@utils/test/index";
import { ether, usdc } from "@utils/common"
import { Account } from "@utils/test";

import { GuaranteedMinimumPayoutCalculator } from "@utils/contracts";
import { takeSnapshot, SnapshotRestorer } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { Address, DrawingTierInfo } from "@utils/types";
import { calculateTotalDrawingPayout } from "@utils/protocolUtils";
import { ADDRESS_ZERO } from "@utils/constants";

const expect = getWaffleExpect();

describe("GuaranteedMinimumPayoutCalculator", () => {
  let owner: Account;
  let user: Account;
  let mockJackpot: Account;

  let payoutCalculator: GuaranteedMinimumPayoutCalculator;

  let snapshot: SnapshotRestorer;
  let deployer: DeployHelper;

  const minimumPayout: bigint = usdc(1);
  const premiumTierMinAllocation: bigint = ether(.2);
  const premiumTierWeights = [
    ether(0),
    ether(0),
    ether(0),
    ether(0.30),
    ether(0.12),
    ether(0.05),
    ether(0.05),
    ether(0.02),
    ether(0.02),
    ether(0.01),
    ether(0.04),
    ether(0.39),
  ];
  const minPayoutTiers = [
    false,
    true,
    false,
    true,
    true,
    true,
    true,
    true,
    true,
    true,
    true,
    false
  ];

  beforeEach(async () => {
    [
      owner,
      mockJackpot,
      user
    ] = await getAccounts();
    deployer = new DeployHelper(owner.wallet);

    payoutCalculator = await deployer.deployGuaranteedMinimumPayoutCalculator(
      mockJackpot.address,
      minimumPayout,
      premiumTierMinAllocation,
      minPayoutTiers,
      premiumTierWeights
    );

    snapshot = await takeSnapshot();
  });

  beforeEach(async () => {
    await snapshot.restore();
  });

  describe("#constructor", async () => {
    let subjectJackpot: Address;
    let subjectMinimumPayout: bigint;
    let subjectPremiumTierMinAllocation: bigint;
    let subjectMinPayoutTiers: boolean[];
    let subjectPremiumTierWeights: bigint[];
    beforeEach(async () => {
      subjectJackpot = mockJackpot.address;
      subjectMinimumPayout = minimumPayout;
      subjectPremiumTierMinAllocation = premiumTierMinAllocation;
      subjectMinPayoutTiers = minPayoutTiers;
      subjectPremiumTierWeights = premiumTierWeights;
    });

    async function subject(): Promise<GuaranteedMinimumPayoutCalculator> {
      return await deployer.deployGuaranteedMinimumPayoutCalculator(
        subjectJackpot,
        subjectMinimumPayout,
        subjectPremiumTierMinAllocation,
        subjectMinPayoutTiers,
        subjectPremiumTierWeights
      );
    }

    it("should set the correct state variables", async () => {
      const payoutCalculator: GuaranteedMinimumPayoutCalculator = await subject();

      const actualJackpot = await payoutCalculator.jackpot();
      const actualMinimumPayout = await payoutCalculator.minimumPayout();
      const actualPremiumTierMinAllocation = await payoutCalculator.premiumTierMinAllocation();
      const actualMinPayoutTiers = await payoutCalculator.getMinPayoutTiers();
      const actualPremiumTierWeights = await payoutCalculator.getPremiumTierWeights();

      expect(actualJackpot).to.equal(mockJackpot.address);
      expect(actualMinimumPayout).to.equal(minimumPayout);
      expect(actualPremiumTierMinAllocation).to.equal(premiumTierMinAllocation);
      expect(actualMinPayoutTiers).to.deep.equal(minPayoutTiers);
      expect(actualPremiumTierWeights).to.deep.equal(premiumTierWeights);
    });

    describe("when the premium tier minimum allocation is greater than 100%", async () => {
      beforeEach(async () => {
        subjectPremiumTierMinAllocation = ether(1.1);
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(payoutCalculator, "InvalidPremiumTierMinimumAllocation");
      });
    });

    describe("when the jackpot address is the zero address", async () => {
      beforeEach(async () => {
        subjectJackpot = ADDRESS_ZERO;
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(payoutCalculator, "ZeroAddress");
      });
    });
  });

  describe("#setDrawingTierInfo", async () => {
    let subjectDrawingId: bigint;
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectDrawingId = BigInt(1);
      subjectCaller = mockJackpot;
    });
    
    async function subject() {
      return await payoutCalculator.connect(subjectCaller.wallet).setDrawingTierInfo(subjectDrawingId);
    }

    it("should set the drawing tier info", async () => {
      await subject();

      const actualDrawingTierInfo: DrawingTierInfo = await payoutCalculator.getDrawingTierInfo(subjectDrawingId);
      expect(actualDrawingTierInfo.minPayout).to.equal(minimumPayout);
      expect(actualDrawingTierInfo.premiumTierMinAllocation).to.equal(premiumTierMinAllocation);
      expect(actualDrawingTierInfo.minPayoutTiers).to.deep.equal(minPayoutTiers);
      expect(actualDrawingTierInfo.premiumTierWeights).to.deep.equal(premiumTierWeights);
    });

    describe("when the caller is not the jackpot", async () => {
      beforeEach(async () => {
        subjectCaller = user;
      });
      
      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(payoutCalculator, "UnauthorizedCaller");
      });
    });
  });

  describe("#calculateAndStoreDrawingUserWinnings", async () => {
    let subjectDrawingId: bigint;
    let subjectPrizePool: bigint;
    let subjectNormalMax: bigint;
    let subjectBonusballMax: bigint;
    let subjectResult: bigint[];
    let subjectDupResult: bigint[];
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectDrawingId = BigInt(1);
      await payoutCalculator.connect(mockJackpot.wallet).setDrawingTierInfo(subjectDrawingId);

      subjectPrizePool = usdc(2000000);
      subjectNormalMax = BigInt(35);
      subjectBonusballMax = BigInt(9);
      subjectResult = [BigInt(1), BigInt(1), BigInt(1), BigInt(1), BigInt(1), BigInt(1), BigInt(1), BigInt(1), BigInt(1), BigInt(1), BigInt(1), BigInt(1)];
      subjectDupResult = [BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0)];
      subjectCaller = mockJackpot;
    });

    async function subject() {
      return await payoutCalculator.connect(subjectCaller.wallet).calculateAndStoreDrawingUserWinnings(
        subjectDrawingId,
        subjectPrizePool,
        subjectNormalMax,
        subjectBonusballMax,
        subjectResult,
        subjectDupResult
      );
    }

    async function subjectStatic() {
      return await payoutCalculator.connect(subjectCaller.wallet).calculateAndStoreDrawingUserWinnings.staticCall(
        subjectDrawingId,
        subjectPrizePool,
        subjectNormalMax,
        subjectBonusballMax,
        subjectResult,
        subjectDupResult
      );
    }

    it("should return the correct total payout", async () => {
      const actualTotalPayout = await subjectStatic();

      const expectedTotalPayout = calculateTotalDrawingPayout(
        subjectPrizePool,
        subjectNormalMax,
        subjectBonusballMax,
        subjectResult,
        subjectDupResult,
        minimumPayout,
        minPayoutTiers,
        premiumTierWeights,
      );

      expect(actualTotalPayout).to.equal(expectedTotalPayout.totalPayout);
    });
    
    it("should calculate and store the correct winnings for a minimum payout tier", async () => {
      await subject();

      const actualTotalPayout = await payoutCalculator.getTierPayout(subjectDrawingId, 1);
      expect(actualTotalPayout).to.equal(usdc(1));
    });

    it("should calculate and store the correct winnings for a no payout tier", async () => {
      await subject();

      const actualTotalPayoutZero = await payoutCalculator.getTierPayout(subjectDrawingId, 0);
      const actualTotalPayoutTwo = await payoutCalculator.getTierPayout(subjectDrawingId, 2);
      expect(actualTotalPayoutZero).to.equal(usdc(0));
      expect(actualTotalPayoutTwo).to.equal(usdc(0));
    });

    it("should calculate and store the correct winnings for a premium payout tier with minimum payout", async () => {
      await subject();

      const actualTierPayout = await payoutCalculator.getTierPayout(subjectDrawingId, 5);
      const expectedTierPayouts = calculateTotalDrawingPayout(
        subjectPrizePool,
        subjectNormalMax,
        subjectBonusballMax,
        subjectResult,
        subjectDupResult,
        minimumPayout,
        minPayoutTiers,
        premiumTierWeights,
      );

      expect(actualTierPayout).to.equal(expectedTierPayouts.tierPayouts[5]);
    });

    it("should calculate and store the correct winnings for a premium payout tier without minimum payout", async () => {
      await subject();
      const actualTierPayout = await payoutCalculator.getTierPayout(subjectDrawingId, 11);

      const expectedTierPayouts = calculateTotalDrawingPayout(
        subjectPrizePool,
        subjectNormalMax,
        subjectBonusballMax,
        subjectResult,
        subjectDupResult,
        minimumPayout,
        minPayoutTiers,
        premiumTierWeights,
      );
      expect(actualTierPayout).to.equal(expectedTierPayouts.tierPayouts[11]);
    });

    describe("when there are duplicate winners", async () => {
      beforeEach(async () => {
        subjectDupResult = [BigInt(1), BigInt(100), BigInt(1), BigInt(100), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0)];
      });

      it("should return the correct total payout", async () => {
        const actualTotalPayout = await subjectStatic();
  
        const expectedTotalPayout = calculateTotalDrawingPayout(
          subjectPrizePool,
          subjectNormalMax,
          subjectBonusballMax,
          subjectResult,
          subjectDupResult,
          minimumPayout,
          minPayoutTiers,
          premiumTierWeights,
        );
  
        expect(actualTotalPayout).to.equal(expectedTotalPayout.totalPayout);
      });

      it("should calculate and store the correct winnings for a premium payout tier with minimum payout", async () => {
        await subject();

        const actualTierPayout = await payoutCalculator.getTierPayout(subjectDrawingId, 5);
        const expectedTierPayouts = calculateTotalDrawingPayout(
          subjectPrizePool,
          subjectNormalMax,
          subjectBonusballMax,
          subjectResult,
          subjectDupResult,
          minimumPayout,
          minPayoutTiers,
          premiumTierWeights,
        );

        expect(actualTierPayout).to.equal(expectedTierPayouts.tierPayouts[5]);
      });

      it("should calculate and store the correct winnings for a minimum payout tier", async () => {
        await subject();
  
        const actualTotalPayout = await payoutCalculator.getTierPayout(subjectDrawingId, 1);
        expect(actualTotalPayout).to.equal(usdc(1));
      });

      it("should calculate and store the correct winnings for a premium payout tier without minimum payout", async () => {
        await subject();
        const actualTierPayout = await payoutCalculator.getTierPayout(subjectDrawingId, 11);
        const expectedTierPayouts = calculateTotalDrawingPayout(
          subjectPrizePool,
          subjectNormalMax,
          subjectBonusballMax,
          subjectResult,
          subjectDupResult,
          minimumPayout,
          minPayoutTiers,
          premiumTierWeights,
        );
        expect(actualTierPayout).to.equal(expectedTierPayouts.tierPayouts[11]);
      });
    });

    describe("when the minimum payout allocation is greater than the prize pool", async () => {
      beforeEach(async () => {
        subjectPrizePool = usdc(200000);
      });

      it("should return the correct total payout", async () => {
        const actualTotalPayout = await subjectStatic();

        const expectedTotalPayout = calculateTotalDrawingPayout(
          subjectPrizePool,
          subjectNormalMax,
          subjectBonusballMax,
          subjectResult,
          subjectDupResult,
          BigInt(0),
          minPayoutTiers,
          premiumTierWeights,
        );
  
        expect(actualTotalPayout).to.equal(expectedTotalPayout.totalPayout);
      });

      it("should calculate and store the correct winnings for a premium payout tier with minimum payout", async () => {
        await subject();

        const actualTierPayout = await payoutCalculator.getTierPayout(subjectDrawingId, 5);
        const expectedTierPayouts = calculateTotalDrawingPayout(
          subjectPrizePool,
          subjectNormalMax,
          subjectBonusballMax,
          subjectResult,
          subjectDupResult,
          BigInt(0),
          minPayoutTiers,
          premiumTierWeights,
        );

        expect(actualTierPayout).to.equal(expectedTierPayouts.tierPayouts[5]);
      });

      it("should calculate and store the correct winnings for a minimum payout tier", async () => {
        await subject();
  
        const actualTotalPayout = await payoutCalculator.getTierPayout(subjectDrawingId, 1);
        expect(actualTotalPayout).to.equal(usdc(0));
      });

      it("should calculate and store the correct winnings for a premium payout tier without minimum payout", async () => {
        await subject();
        const actualTierPayout = await payoutCalculator.getTierPayout(subjectDrawingId, 11);

        const expectedTierPayouts = calculateTotalDrawingPayout(
          subjectPrizePool,
          subjectNormalMax,
          subjectBonusballMax,
          subjectResult,
          subjectDupResult,
          BigInt(0),
          minPayoutTiers,
          premiumTierWeights,
        );
        expect(actualTierPayout).to.equal(expectedTierPayouts.tierPayouts[11]);
      });
    });

    describe("when the minimum payout allocation + minimum premium allocation is greater than the prize pool", async () => {
      beforeEach(async () => {
        // 685k in guaranteed minimums + 140k in premium tier allocation = 825k > 700k
        subjectPrizePool = usdc(700000);
      });

      it("should return the correct total payout", async () => {
        const actualTotalPayout = await subjectStatic();

        const expectedTotalPayout = calculateTotalDrawingPayout(
          subjectPrizePool,
          subjectNormalMax,
          subjectBonusballMax,
          subjectResult,
          subjectDupResult,
          BigInt(0),
          minPayoutTiers,
          premiumTierWeights,
        );
  
        expect(actualTotalPayout).to.equal(expectedTotalPayout.totalPayout);
      });

      it("should calculate and store the correct winnings for a premium payout tier with minimum payout", async () => {
        await subject();

        const actualTierPayout = await payoutCalculator.getTierPayout(subjectDrawingId, 5);
        const expectedTierPayouts = calculateTotalDrawingPayout(
          subjectPrizePool,
          subjectNormalMax,
          subjectBonusballMax,
          subjectResult,
          subjectDupResult,
          BigInt(0),
          minPayoutTiers,
          premiumTierWeights,
        );

        expect(actualTierPayout).to.equal(expectedTierPayouts.tierPayouts[5]);
      });

      it("should calculate and store the correct winnings for a minimum payout tier", async () => {
        await subject();
  
        const actualTotalPayout = await payoutCalculator.getTierPayout(subjectDrawingId, 1);
        expect(actualTotalPayout).to.equal(usdc(0));
      });

      it("should calculate and store the correct winnings for a premium payout tier without minimum payout", async () => {
        await subject();
        const actualTierPayout = await payoutCalculator.getTierPayout(subjectDrawingId, 11);

        const expectedTierPayouts = calculateTotalDrawingPayout(
          subjectPrizePool,
          subjectNormalMax,
          subjectBonusballMax,
          subjectResult,
          subjectDupResult,
          BigInt(0),
          minPayoutTiers,
          premiumTierWeights,
        );
        expect(actualTierPayout).to.equal(expectedTierPayouts.tierPayouts[11]);
      });
    });

    describe("when there are duplicate winners and the minimum payout allocation is greater than the prize pool", async () => {
      beforeEach(async () => {
        subjectDupResult = [BigInt(1), BigInt(100), BigInt(1), BigInt(100), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(0), BigInt(1), BigInt(0), BigInt(0)];
        subjectPrizePool = usdc(200000);
      });

      it("should return the correct total payout", async () => {
        const actualTotalPayout = await subjectStatic();
  
        const expectedTotalPayout = calculateTotalDrawingPayout(
          subjectPrizePool,
          subjectNormalMax,
          subjectBonusballMax,
          subjectResult,
          subjectDupResult,
          BigInt(0),
          minPayoutTiers,
          premiumTierWeights,
        );
  
        expect(actualTotalPayout).to.equal(expectedTotalPayout.totalPayout);
      });

      it("should calculate and store the correct winnings for a premium payout tier with minimum payout", async () => {
        await subject();

        const actualTierPayout = await payoutCalculator.getTierPayout(subjectDrawingId, 5);
        const expectedTierPayouts = calculateTotalDrawingPayout(
          subjectPrizePool,
          subjectNormalMax,
          subjectBonusballMax,
          subjectResult,
          subjectDupResult,
          BigInt(0),
          minPayoutTiers,
          premiumTierWeights,
        );

        expect(actualTierPayout).to.equal(expectedTierPayouts.tierPayouts[5]);
      });

      it("should calculate and store the correct winnings for a minimum payout tier", async () => {
        await subject();
  
        const actualTotalPayout = await payoutCalculator.getTierPayout(subjectDrawingId, 1);
        expect(actualTotalPayout).to.equal(usdc(0));
      });

      it("should calculate and store the correct winnings for a premium payout tier without minimum payout", async () => {
        await subject();
        const actualTierPayout = await payoutCalculator.getTierPayout(subjectDrawingId, 11);
        const expectedTierPayouts = calculateTotalDrawingPayout(
          subjectPrizePool,
          subjectNormalMax,
          subjectBonusballMax,
          subjectResult,
          subjectDupResult,
          BigInt(0),
          minPayoutTiers,
          premiumTierWeights,
        );
        expect(actualTierPayout).to.equal(expectedTierPayouts.tierPayouts[11]);
      });
    });

    describe("when the caller is not the jackpot", async () => {
      beforeEach(async () => {
        subjectCaller = user;
      });
      
      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(payoutCalculator, "UnauthorizedCaller");
      });
    });
  });

  describe("#setMinimumPayout", async () => {
    let subjectMinimumPayout: bigint;
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectMinimumPayout = usdc(2);
      subjectCaller = owner;
    });
    
    async function subject() {
      return await payoutCalculator.connect(subjectCaller.wallet).setMinimumPayout(subjectMinimumPayout);
    }

    it("should set the minimum payout", async () => {
      await subject();

      const actualMinimumPayout = await payoutCalculator.minimumPayout();
      expect(actualMinimumPayout).to.equal(subjectMinimumPayout);
    });

    describe("when the caller is not the owner", async () => {
      beforeEach(async () => {
        subjectCaller = user;
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(payoutCalculator, "OwnableUnauthorizedAccount");
      });
    });
  });

  describe("#setPremiumTierMinAllocation", async () => {
    let subjectPremiumTierMinAllocation: bigint;
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectPremiumTierMinAllocation = ether(.15);
      subjectCaller = owner;
    });
    
    async function subject() {
      return await payoutCalculator.connect(subjectCaller.wallet).setPremiumTierMinAllocation(subjectPremiumTierMinAllocation);
    }

    it("should set the premium tier minimum allocation", async () => {
      await subject();

      const actualPremiumTierMinAllocation = await payoutCalculator.premiumTierMinAllocation();
      expect(actualPremiumTierMinAllocation).to.equal(subjectPremiumTierMinAllocation);
    });

    describe("when the premium tier minimum allocation is greater than 100%", async () => {
      beforeEach(async () => {
        subjectPremiumTierMinAllocation = ether(1.1);
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(payoutCalculator, "InvalidPremiumTierMinimumAllocation");
      });
    });

    describe("when the caller is not the owner", async () => {
      beforeEach(async () => {
        subjectCaller = user;
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(payoutCalculator, "OwnableUnauthorizedAccount");
      });
    });
  });

  describe("#setMinPayoutTiers", async () => {
    let subjectMinPayoutTiers: boolean[];
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectMinPayoutTiers = [true, true, true, true, true, true, true, true, true, true, true, true];
      subjectCaller = owner;
    });
    
    async function subject() {
      return await payoutCalculator.connect(subjectCaller.wallet).setMinPayoutTiers(subjectMinPayoutTiers);
    }

    it("should set the minimum payout", async () => {
      await subject();

      const actualMinimumPayout = await payoutCalculator.getMinPayoutTiers();
      expect(actualMinimumPayout).to.deep.equal(subjectMinPayoutTiers); 
    });

    describe("when the caller is not the owner", async () => {
      beforeEach(async () => {
        subjectCaller = user;
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(payoutCalculator, "OwnableUnauthorizedAccount");
      });
    });
  });

  describe("#setPremiumTierWeights", async () => {
    let subjectPremiumTierWeights: bigint[];
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectPremiumTierWeights = [
        ether(0),
        ether(0),
        ether(0),
        ether(0.1),
        ether(0.17),
        ether(0.12),
        ether(0.12),
        ether(0.03),
        ether(0.02),
        ether(0.01),
        ether(0.04),
        ether(0.39),
      ];
      subjectCaller = owner;
    });
    
    async function subject() {
      return await payoutCalculator.connect(subjectCaller.wallet).setPremiumTierWeights(subjectPremiumTierWeights);
    }

    it("should set the minimum payout", async () => {
      await subject();

      const actualMinimumPayout = await payoutCalculator.getPremiumTierWeights();
      expect(actualMinimumPayout).to.deep.equal(subjectPremiumTierWeights); 
    });

    describe("when the sum of the weights does not equal 1", async () => {
      beforeEach(async () => {
        subjectPremiumTierWeights[11] = ether(0.1);
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(payoutCalculator, "InvalidTierWeights");
      });
    });

    describe("when the caller is not the owner", async () => {
      beforeEach(async () => {
        subjectCaller = user;
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(payoutCalculator, "OwnableUnauthorizedAccount");
      });
    });
  });
});
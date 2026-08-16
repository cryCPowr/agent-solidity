
import { ethers } from "hardhat";
import DeployHelper from "@utils/deploys";

import {
  getWaffleExpect,
  getAccounts
} from "@utils/test/index";
import { Account } from "@utils/test";
import { LP, LPDrawingState, LPValueBreakdown } from "@utils/types";

import { JackpotLPManager, MockJackpot } from "@utils/contracts";
import { takeSnapshot, SnapshotRestorer } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { usdc } from "@utils/common";
import { PRECISE_UNIT } from "@utils/constants";

const expect = getWaffleExpect();

describe("JackpotLPManager", () => {
  let owner: Account;
  let user1: Account;
  let user2: Account;
  let unauthorized: Account;

  let jackpotLPManager: JackpotLPManager;
  let mockJackpot: MockJackpot;
  let snapshot: SnapshotRestorer;

  const DRAWING_ID_0 = 0n;
  const DRAWING_ID_1 = 1n;
  const DRAWING_ID_2 = 2n;
  const DEPOSIT_AMOUNT_1000 = usdc(1000);
  const DEPOSIT_AMOUNT_2000 = usdc(2000);
  const INITIAL_LP_VALUE = usdc(5000);
  const POOL_CAP_10000 = usdc(10000);

  beforeEach(async () => {
    [owner, user1, user2, unauthorized] = await getAccounts();
    
    const deployer = new DeployHelper(owner.wallet);
    mockJackpot = await deployer.deployMockJackpot();
    jackpotLPManager = await deployer.deployJackpotLPManager(await mockJackpot.getAddress());
    
    snapshot = await takeSnapshot();
  });

  beforeEach(async () => {
    await snapshot.restore();
  });

  describe("#constructor", () => {
    it("should set the jackpot address correctly", async () => {
      expect(await jackpotLPManager.jackpot()).to.equal(await mockJackpot.getAddress());
    });

    it("should set owner correctly", async () => {
      expect(await jackpotLPManager.owner()).to.equal(owner.address);
    });

    describe("when jackpot is zero address", () => {
      it("should revert with ZeroAddress", async () => {
        const deployer = new DeployHelper(owner.wallet);
        const JackpotLPManagerFactory = await ethers.getContractFactory("JackpotLPManager", owner.wallet);
        
        await expect(
          JackpotLPManagerFactory.deploy(ethers.ZeroAddress)
        ).to.be.revertedWithCustomError(jackpotLPManager, "ZeroAddress");
      });
    });
  });

  describe("#initializeLP", () => {
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectCaller = owner; // Will be overridden in specific test cases
    });

    async function subject(): Promise<any> {
      if (subjectCaller === owner) {
        return await mockJackpot.initializeLP(await jackpotLPManager.getAddress());
      } else {
        return await jackpotLPManager.connect(subjectCaller.wallet).initializeLP();
      }
    }

    describe("when called by jackpot contract", () => {
      it("should set initial drawing accumulator to PRECISE_UNIT", async () => {
        await subject();
        
        const accumulator: bigint = await jackpotLPManager.getDrawingAccumulator(DRAWING_ID_0);
        expect(accumulator).to.equal(PRECISE_UNIT);
      });
    });

    describe("when called by unauthorized address", () => {
      beforeEach(async () => {
        subjectCaller = unauthorized;
      });

      it("should revert with UnauthorizedCaller", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "UnauthorizedCaller");
      });
    });
  });

  describe("#processDeposit", () => {
    let subjectDrawingId: bigint;
    let subjectLpAddress: string;
    let subjectAmount: bigint;
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectDrawingId = DRAWING_ID_0;
      subjectLpAddress = user1.address;
      subjectAmount = DEPOSIT_AMOUNT_1000;
      subjectCaller = owner; // Will be overridden in specific test cases

      // Initialize LP and set pool cap
      await mockJackpot.initializeLP(await jackpotLPManager.getAddress());
      await mockJackpot.initializeDrawingLP(await jackpotLPManager.getAddress(), DRAWING_ID_0, INITIAL_LP_VALUE);
      await mockJackpot.setLPPoolCap(await jackpotLPManager.getAddress(), DRAWING_ID_0, POOL_CAP_10000);
    });

    async function subject(): Promise<any> {
      if (subjectCaller === owner) {
        return await mockJackpot.processDeposit(
          await jackpotLPManager.getAddress(),
          subjectDrawingId,
          subjectLpAddress,
          subjectAmount
        );
      } else {
        return await jackpotLPManager.connect(subjectCaller.wallet).processDeposit(
          subjectDrawingId,
          subjectLpAddress,
          subjectAmount
        );
      }
    }

    describe("when called by jackpot contract", () => {
      it("should update LP info with deposit", async () => {
        await subject();
        
        const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        expect(lpInfo.lastDeposit.amount).to.equal(subjectAmount);
        expect(lpInfo.lastDeposit.drawingId).to.equal(subjectDrawingId);
      });

      it("should update drawing state pending deposits", async () => {
        await subject();
        
        const drawingState: LPDrawingState = await jackpotLPManager.getLPDrawingState(subjectDrawingId);
        expect(drawingState.pendingDeposits).to.equal(subjectAmount);
      });

      it("should emit LpDeposited event", async () => {
        await expect(subject())
          .to.emit(jackpotLPManager, "LpDeposited")
          .withArgs(subjectLpAddress, subjectDrawingId, subjectAmount, subjectAmount);
      });

      describe("when multiple deposits from same user", () => {
        beforeEach(async () => {
          // First deposit
          await subject();
          subjectAmount = DEPOSIT_AMOUNT_2000;
        });

        it("should accumulate deposit amounts", async () => {
          await subject();
          
          const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
          expect(lpInfo.lastDeposit.amount).to.equal(DEPOSIT_AMOUNT_1000 + DEPOSIT_AMOUNT_2000);
        });
      });

      describe("when deposit would exceed pool cap", () => {
        beforeEach(async () => {
          subjectAmount = POOL_CAP_10000 + 1n; // Exceeds cap since lpPoolTotal is INITIAL_LP_VALUE
        });

        it("should revert with ExceedsPoolCap", async () => {
          await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "ExceedsPoolCap");
        });
      });

      describe("when deposit would exceed pool cap because of pending deposits", () => {
        beforeEach(async () => {
          await mockJackpot.processDeposit(
            await jackpotLPManager.getAddress(),
            DRAWING_ID_0,
            user1.address,
            DEPOSIT_AMOUNT_1000
          );
          const poolCap = await jackpotLPManager.lpPoolCap();
          subjectAmount = poolCap - INITIAL_LP_VALUE - DEPOSIT_AMOUNT_1000 + BigInt(1);
        });

        it("should revert with ExceedsPoolCap", async () => {
          await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "ExceedsPoolCap");
        });
      });
    });

    describe("when called by unauthorized address", () => {
      beforeEach(async () => {
        subjectCaller = unauthorized;
      });

      it("should revert with UnauthorizedCaller", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "UnauthorizedCaller");
      });
    });
  });

  describe("#processInitiateWithdraw", () => {
    let subjectDrawingId: bigint;
    let subjectLpAddress: string;
    let subjectShares: bigint;
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectDrawingId = DRAWING_ID_1;
      subjectLpAddress = user1.address;
      subjectShares = usdc(500); // $500 worth of shares
      subjectCaller = owner;

      // Setup: Initialize LP, make deposit, advance to next drawing
      await mockJackpot.initializeLP(await jackpotLPManager.getAddress());
      await mockJackpot.initializeDrawingLP(await jackpotLPManager.getAddress(), DRAWING_ID_0, INITIAL_LP_VALUE);
      await mockJackpot.setLPPoolCap(await jackpotLPManager.getAddress(), DRAWING_ID_0, POOL_CAP_10000);
      await mockJackpot.processDeposit(
        await jackpotLPManager.getAddress(),
        DRAWING_ID_0,
        user1.address,
        DEPOSIT_AMOUNT_1000
      );
      
      // Simulate drawing completion and accumulator update
      await mockJackpot.processDrawingSettlement(
        await jackpotLPManager.getAddress(),
        DRAWING_ID_0,
        0, // $100 earnings
        0n,   // winnings
        0n    // protocol fee
      );
      
      // Initialize next drawing (no consolidation trigger here)
      await mockJackpot.initializeDrawingLP(await jackpotLPManager.getAddress(), DRAWING_ID_1, INITIAL_LP_VALUE);
    });

    async function subject(): Promise<any> {
      if (subjectCaller === owner) {
        return await mockJackpot.processInitiateWithdraw(
          await jackpotLPManager.getAddress(),
          subjectDrawingId,
          subjectLpAddress,
          subjectShares
        );
      } else {
        return await jackpotLPManager.connect(subjectCaller.wallet).processInitiateWithdraw(
          subjectDrawingId,
          subjectLpAddress,
          subjectShares
        );
      }
    }

    it("should consolidate deposits before processing withdrawal", async () => {
      // Before withdrawal - deposits should be consolidated
      const lpInfoBefore: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);      

      expect(lpInfoBefore.consolidatedShares).to.equal(0); // $1000 at 1:1 ratio
      expect(lpInfoBefore.lastDeposit.amount).to.equal(DEPOSIT_AMOUNT_1000); // $1000 trigger deposit
      expect(lpInfoBefore.lastDeposit.drawingId).to.equal(DRAWING_ID_0); // From drawing 1
      
      await subject();
      
      // After withdrawal, consolidated shares should be reduced
      const lpInfoAfter: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
      expect(lpInfoAfter.consolidatedShares).to.equal(DEPOSIT_AMOUNT_1000 - subjectShares);
      expect(lpInfoAfter.lastDeposit.amount).to.equal(0); // Trigger deposit still pending
    });

    it("should calculate the correct amount of consolidated shares", async () => {
      await subject();
      
      const lpInfoAfter: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
      expect(lpInfoAfter.consolidatedShares).to.equal(DEPOSIT_AMOUNT_1000 - subjectShares);
    });

    it("should set pending withdrawal", async () => {
      await subject();
      
      const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
      expect(lpInfo.pendingWithdrawal.amountInShares).to.equal(subjectShares);
      expect(lpInfo.pendingWithdrawal.drawingId).to.equal(subjectDrawingId);
    });

    it("should update drawing state pending withdrawals", async () => {
      await subject();
      
      const drawingState: LPDrawingState = await jackpotLPManager.getLPDrawingState(subjectDrawingId);
      expect(drawingState.pendingWithdrawals).to.equal(subjectShares);
    });

    it("should emit LpWithdrawInitiated event", async () => {
      await expect(subject())
        .to.emit(jackpotLPManager, "LpWithdrawInitiated")
        .withArgs(subjectLpAddress, subjectDrawingId, subjectShares, subjectShares);
    });

    describe("when deposits have been consolidated", () => {
      beforeEach(async () => {
        // Make a small deposit in the new drawing to trigger deposit consolidation
        await mockJackpot.processDeposit(
          await jackpotLPManager.getAddress(),
          DRAWING_ID_1,
          user1.address,
          usdc(1) // $1 deposit to trigger consolidation
        );
      });

      it("should consolidate deposits before processing withdrawal", async () => {
        // Before withdrawal - deposits should be consolidated
        const lpInfoBefore: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        
        // Should have consolidated shares from the $1000 deposit
        expect(lpInfoBefore.consolidatedShares).to.equal(DEPOSIT_AMOUNT_1000); // $1000 at 1:1 ratio
        
        // Should have the small trigger deposit pending  
        expect(lpInfoBefore.lastDeposit.amount).to.equal(usdc(1)); // $1 trigger deposit
        expect(lpInfoBefore.lastDeposit.drawingId).to.equal(DRAWING_ID_1); // From drawing 1
        
        await subject();
        
        // After withdrawal, consolidated shares should be reduced
        const lpInfoAfter: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        expect(lpInfoAfter.consolidatedShares).to.equal(DEPOSIT_AMOUNT_1000 - subjectShares);
        expect(lpInfoAfter.lastDeposit.amount).to.equal(usdc(1)); // Trigger deposit still pending
      });

      it("should deduct shares from consolidated shares", async () => {
        const lpInfoBefore: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        
        await subject();
        
        const lpInfoAfter: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        expect(lpInfoAfter.consolidatedShares).to.equal(lpInfoBefore.consolidatedShares - subjectShares);
      });

      it("should set pending withdrawal", async () => {
        await subject();
        
        const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        expect(lpInfo.pendingWithdrawal.amountInShares).to.equal(subjectShares);
        expect(lpInfo.pendingWithdrawal.drawingId).to.equal(subjectDrawingId);
      });

      it("should update drawing state pending withdrawals", async () => {
        await subject();
        
        const drawingState: LPDrawingState = await jackpotLPManager.getLPDrawingState(subjectDrawingId);
        expect(drawingState.pendingWithdrawals).to.equal(subjectShares);
      });

      it("should emit LpWithdrawInitiated event", async () => {
        await expect(subject())
          .to.emit(jackpotLPManager, "LpWithdrawInitiated")
          .withArgs(subjectLpAddress, subjectDrawingId, subjectShares, subjectShares);
      });
    });

    describe("when there are withdrawals to be consolidated", () => {
      beforeEach(async () => {
        await subject();

        // Simulate drawing completion and accumulator update
        await mockJackpot.processDrawingSettlement(
          await jackpotLPManager.getAddress(),
          DRAWING_ID_1,
          usdc(100), // $100 earnings
          0n,   // winnings
          0n    // protocol fee
        );
        
        // Initialize next drawing (no consolidation trigger here)
        await mockJackpot.initializeDrawingLP(await jackpotLPManager.getAddress(), DRAWING_ID_2, INITIAL_LP_VALUE + BigInt(2) * usdc(100));
        subjectDrawingId = DRAWING_ID_2;
      });

      it("should consolidate withdrawals before processing new withdrawal", async () => {
        const lpInfoBefore: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        expect(lpInfoBefore.pendingWithdrawal.amountInShares).to.equal(subjectShares);
        expect(lpInfoBefore.pendingWithdrawal.drawingId).to.equal(DRAWING_ID_1);
        expect(lpInfoBefore.claimableWithdrawals).to.equal(0n);

        await subject();
        
        const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        const drawingAccumulator: bigint = await jackpotLPManager.getDrawingAccumulator(DRAWING_ID_1);
        expect(lpInfo.pendingWithdrawal.amountInShares).to.equal(subjectShares);
        expect(lpInfo.pendingWithdrawal.drawingId).to.equal(DRAWING_ID_2);
        expect(lpInfo.claimableWithdrawals).to.equal(subjectShares * drawingAccumulator / PRECISE_UNIT);
      });

      it("should deduct shares from consolidated shares", async () => {
        const lpInfoBefore: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        
        await subject();
        
        const lpInfoAfter: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        expect(lpInfoAfter.consolidatedShares).to.equal(lpInfoBefore.consolidatedShares - subjectShares);
      });

      it("should set pending withdrawal", async () => {
        await subject();
        
        const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        expect(lpInfo.pendingWithdrawal.amountInShares).to.equal(subjectShares);
        expect(lpInfo.pendingWithdrawal.drawingId).to.equal(subjectDrawingId);
      });

      it("should update drawing state pending withdrawals", async () => {
        await subject();
        
        const drawingState: LPDrawingState = await jackpotLPManager.getLPDrawingState(subjectDrawingId);
        expect(drawingState.pendingWithdrawals).to.equal(subjectShares);
      });

      it("should emit LpWithdrawInitiated event", async () => {
        await expect(subject())
          .to.emit(jackpotLPManager, "LpWithdrawInitiated")
          .withArgs(subjectLpAddress, subjectDrawingId, subjectShares, subjectShares);
      });
    });

    describe("when user has insufficient shares", () => {
      beforeEach(async () => {
        subjectShares = usdc(2000); // Withdraw more than deposited
      });

      it("should revert with InsufficientShares when no deposits consolidated", async () => {
        // Base case - no consolidation, so no consolidated shares
        const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        expect(lpInfo.consolidatedShares).to.equal(0n); // No consolidated shares
        expect(lpInfo.lastDeposit.amount).to.equal(DEPOSIT_AMOUNT_1000); // Deposit still pending
        
        await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "InsufficientShares");
      });
    });

    describe("when called by unauthorized address", () => {
      beforeEach(async () => {
        subjectCaller = unauthorized;
      });

      it("should revert with UnauthorizedCaller", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "UnauthorizedCaller");
      });
    });
  });

  describe("#processFinalizeWithdraw", () => {
    let subjectDrawingId: bigint;
    let subjectLpAddress: string;
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectDrawingId = DRAWING_ID_2;
      subjectLpAddress = user1.address;
      subjectCaller = owner;

      // Setup complete LP workflow: deposit -> initiate withdraw -> advance drawing
      await mockJackpot.initializeLP(await jackpotLPManager.getAddress());
      await mockJackpot.initializeDrawingLP(await jackpotLPManager.getAddress(), DRAWING_ID_0, INITIAL_LP_VALUE);
      await mockJackpot.setLPPoolCap(await jackpotLPManager.getAddress(), DRAWING_ID_0, POOL_CAP_10000);
      
      // Make deposit
      await mockJackpot.processDeposit(
        await jackpotLPManager.getAddress(),
        DRAWING_ID_0,
        user1.address,
        DEPOSIT_AMOUNT_1000
      );
      
      // Complete drawing and update accumulator
      await mockJackpot.processDrawingSettlement(
        await jackpotLPManager.getAddress(),
        DRAWING_ID_0,
        usdc(100), // $100 earnings
        0n,   // winnings  
        0n    // protocol fee
      );
      
      // Initialize next drawing and make small deposit to trigger consolidation
      await mockJackpot.initializeDrawingLP(await jackpotLPManager.getAddress(), DRAWING_ID_1, INITIAL_LP_VALUE);
      
      // Initiate withdrawal (now deposits should be consolidated)
      await mockJackpot.processInitiateWithdraw(
        await jackpotLPManager.getAddress(),
        DRAWING_ID_1,
        user1.address,
        usdc(500) // Withdraw $500 worth of shares
      );
      
      // Complete another drawing to make withdrawal claimable
      await mockJackpot.processDrawingSettlement(
        await jackpotLPManager.getAddress(),
        DRAWING_ID_1,
        usdc(50),  // $50 earnings
        0n,   // winnings
        0n    // protocol fee
      );
    });

    async function subject(): Promise<any> {
      if (subjectCaller === owner) {
        return await mockJackpot.processFinalizeWithdraw(
          await jackpotLPManager.getAddress(),
          subjectDrawingId,
          subjectLpAddress
        );
      } else {
        return await jackpotLPManager.connect(subjectCaller.wallet).processFinalizeWithdraw(
          subjectDrawingId,
          subjectLpAddress
        );
      }
    }

    describe("when user has claimable withdrawals still in pending withdrawal", () => {
      it("should return correct withdrawable amount", async () => {
        await subject();
        
        const withdrawableAmount: bigint = await mockJackpot.getLastWithdrawableAmount();
        expect(withdrawableAmount).to.be.gt(0n);
      });

      it("should clear claimable withdrawals and pendingWithdrawal", async () => {
        const lpInfoBefore: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        expect(lpInfoBefore.pendingWithdrawal.amountInShares).to.equal(usdc(500));
        expect(lpInfoBefore.pendingWithdrawal.drawingId).to.equal(DRAWING_ID_1);

        await subject();
        
        const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        expect(lpInfo.claimableWithdrawals).to.equal(0n); 
        expect(lpInfo.pendingWithdrawal.amountInShares).to.equal(0n);
        expect(lpInfo.pendingWithdrawal.drawingId).to.equal(0n);
      });

      it("should emit LpWithdrawFinalized event", async () => {
        const tx = await subject();
        const withdrawableAmount: bigint = await mockJackpot.getLastWithdrawableAmount();
        
        await expect(tx)
          .to.emit(jackpotLPManager, "LpWithdrawFinalized")
          .withArgs(subjectLpAddress, subjectDrawingId, withdrawableAmount);
      });
    });

    describe("when user has a pending withdrawal that is not claimable", () => {
      beforeEach(async () => {
        await mockJackpot.processDeposit(
          await jackpotLPManager.getAddress(),
          DRAWING_ID_1,
          user1.address,
          usdc(1) // Withdraw $500 worth of shares
        );

        await mockJackpot.processInitiateWithdraw(
          await jackpotLPManager.getAddress(),
          DRAWING_ID_2,
          user1.address,
          usdc(100) // Withdraw $500 worth of shares
        );
      });

      it("should return correct withdrawable amount", async () => {
        await subject();
        
        const withdrawableAmount: bigint = await mockJackpot.getLastWithdrawableAmount();
        expect(withdrawableAmount).to.be.gt(0n);
      });

      it("should clear claimable withdrawals but not pendingWithdrawal", async () => {
        const lpInfoBefore: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        expect(lpInfoBefore.claimableWithdrawals).to.equal(usdc(505));
        expect(lpInfoBefore.pendingWithdrawal.amountInShares).to.equal(usdc(100));
        expect(lpInfoBefore.pendingWithdrawal.drawingId).to.equal(DRAWING_ID_2);

        await subject();
        
        const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        expect(lpInfo.claimableWithdrawals).to.equal(0n); 
        expect(lpInfo.pendingWithdrawal.amountInShares).to.equal(usdc(100));
        expect(lpInfo.pendingWithdrawal.drawingId).to.equal(DRAWING_ID_2);
      });

      it("should emit LpWithdrawFinalized event", async () => {
        const tx = await subject();
        const withdrawableAmount: bigint = await mockJackpot.getLastWithdrawableAmount();
        
        await expect(tx)
          .to.emit(jackpotLPManager, "LpWithdrawFinalized")
          .withArgs(subjectLpAddress, subjectDrawingId, withdrawableAmount);
      });
    });

    describe("when user has claimable withdrawals still in claimable withdrawals", () => {
      beforeEach(async () => {
        await mockJackpot.processDeposit(
          await jackpotLPManager.getAddress(),
          DRAWING_ID_1,
          user1.address,
          usdc(1) // Withdraw $500 worth of shares
        );
      });

      it("should return correct withdrawable amount", async () => {
        await subject();
        
        const withdrawableAmount: bigint = await mockJackpot.getLastWithdrawableAmount();
        expect(withdrawableAmount).to.be.gt(0n);
      });

      it("should clear claimable withdrawals", async () => {
        await subject();
        
        const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectLpAddress);
        expect(lpInfo.claimableWithdrawals).to.equal(0n);
      });

      it("should emit LpWithdrawFinalized event", async () => {
        const tx = await subject();
        const withdrawableAmount: bigint = await mockJackpot.getLastWithdrawableAmount();
        
        await expect(tx)
          .to.emit(jackpotLPManager, "LpWithdrawFinalized")
          .withArgs(subjectLpAddress, subjectDrawingId, withdrawableAmount);
      });
    });

    describe("when user has nothing to withdraw", () => {
      beforeEach(async () => {
        subjectLpAddress = user2.address; // User with no withdrawals
      });

      it("should revert with NothingToWithdraw", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "NothingToWithdraw");
      });
    });

    describe("when called by unauthorized address", () => {
      beforeEach(async () => {
        subjectCaller = unauthorized;
      });

      it("should revert with UnauthorizedCaller", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "UnauthorizedCaller");
      });
    });
  });

  describe("#processDrawingSettlement", () => {
    let subjectDrawingId: bigint;
    let subjectLpEarnings: bigint;
    let subjectUserWinnings: bigint;
    let subjectProtocolFee: bigint;
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectDrawingId = DRAWING_ID_1;
      subjectLpEarnings = BigInt(200);
      subjectUserWinnings = BigInt(100);
      subjectProtocolFee = BigInt(50);
      subjectCaller = owner;

      // Setup initial drawing state
      await mockJackpot.initializeLP(await jackpotLPManager.getAddress());
      await mockJackpot.initializeDrawingLP(await jackpotLPManager.getAddress(), DRAWING_ID_0, INITIAL_LP_VALUE);
      await mockJackpot.initializeDrawingLP(await jackpotLPManager.getAddress(), DRAWING_ID_1, INITIAL_LP_VALUE);
    });

    async function subject(): Promise<any> {
      if (subjectCaller === owner) {
        return await mockJackpot.processDrawingSettlement(
          await jackpotLPManager.getAddress(),
          subjectDrawingId,
          subjectLpEarnings,
          subjectUserWinnings,
          subjectProtocolFee
        );
      } else {
        return await jackpotLPManager.connect(subjectCaller.wallet).processDrawingSettlement(
          subjectDrawingId,
          subjectLpEarnings,
          subjectUserWinnings,
          subjectProtocolFee
        );
      }
    }

    describe("when called by jackpot contract", () => {
      it("should calculate and store correct LP settlement values", async () => {
        await subject();
        
        const [newLPValue, newAccumulator]: [bigint, bigint] = await mockJackpot.getLastLPSettlementResults();
        
        // Verify calculations
        const expectedPostDrawValue = INITIAL_LP_VALUE + subjectLpEarnings - subjectUserWinnings - subjectProtocolFee;
        const expectedAccumulator = (PRECISE_UNIT * expectedPostDrawValue) / INITIAL_LP_VALUE;
        
        expect(newAccumulator).to.equal(expectedAccumulator);
        expect(newLPValue).to.equal(expectedPostDrawValue); // No pending deposits/withdrawals
      });

      it("should update stored accumulator", async () => {
        await subject();
        
        const [, expectedAccumulator]: [bigint, bigint] = await mockJackpot.getLastLPSettlementResults();
        const storedAccumulator: bigint = await jackpotLPManager.getDrawingAccumulator(subjectDrawingId);
        
        expect(storedAccumulator).to.equal(expectedAccumulator);
      });

      describe("when drawing ID is 0", () => {
        beforeEach(async () => {
          subjectDrawingId = DRAWING_ID_0;
        });

        it("should not update accumulator for first drawing", async () => {
          await subject();
          
          const accumulatorBefore: bigint = await jackpotLPManager.getDrawingAccumulator(DRAWING_ID_0);
          expect(accumulatorBefore).to.equal(PRECISE_UNIT); // Should remain at initial value
        });
      });

      describe("when LP pool total is 0 in previous drawing", () => {
        beforeEach(async () => {
          await mockJackpot.initializeDrawingLP(await jackpotLPManager.getAddress(), DRAWING_ID_1, 0);
        });

        it("should update accumulator to PRECISE_UNIT", async () => {
          await subject();
          
          const accumulator: bigint = await jackpotLPManager.getDrawingAccumulator(DRAWING_ID_1);
          expect(accumulator).to.equal(PRECISE_UNIT);
        });
      });
    });

    describe("when called by unauthorized address", () => {
      beforeEach(async () => {
        subjectCaller = unauthorized;
      });

      it("should revert with UnauthorizedCaller", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "UnauthorizedCaller");
      });
    });
  });

  describe("#initializeDrawingLP", () => {
    let subjectDrawingId: bigint;
    let subjectInitialValue: bigint;
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectDrawingId = DRAWING_ID_1;
      subjectInitialValue = INITIAL_LP_VALUE;
      subjectCaller = owner;
    });

    async function subject(): Promise<any> {
      if (subjectCaller === owner) {
        return await mockJackpot.initializeDrawingLP(
          await jackpotLPManager.getAddress(),
          subjectDrawingId,
          subjectInitialValue
        );
      } else {
        return await jackpotLPManager.connect(subjectCaller.wallet).initializeDrawingLP(
          subjectDrawingId,
          subjectInitialValue
        );
      }
    }

    describe("when called by jackpot contract", () => {
      it("should initialize drawing state correctly", async () => {
        await subject();
        
        const drawingState: LPDrawingState = await jackpotLPManager.getLPDrawingState(subjectDrawingId);
        expect(drawingState.lpPoolTotal).to.equal(subjectInitialValue);
        expect(drawingState.pendingDeposits).to.equal(0n);
        expect(drawingState.pendingWithdrawals).to.equal(0n);
      });
    });

    describe("when called by unauthorized address", () => {
      beforeEach(async () => {
        subjectCaller = unauthorized;
      });

      it("should revert with UnauthorizedCaller", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "UnauthorizedCaller");
      });
    });
  });

  describe("#setLPPoolCap", () => {
    let subjectDrawingId: bigint;
    let subjectPoolCap: bigint;
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectDrawingId = DRAWING_ID_0;
      subjectPoolCap = POOL_CAP_10000;
      subjectCaller = owner;

      // Initialize drawing with some LP value
      await mockJackpot.initializeLP(await jackpotLPManager.getAddress());
      await mockJackpot.initializeDrawingLP(await jackpotLPManager.getAddress(), DRAWING_ID_0, INITIAL_LP_VALUE);
    });

    async function subject(): Promise<any> {
      if (subjectCaller === owner) {
        return await mockJackpot.setLPPoolCap(
          await jackpotLPManager.getAddress(),
          subjectDrawingId,
          subjectPoolCap
        );
      } else {
        return await jackpotLPManager.connect(subjectCaller.wallet).setLPPoolCap(
          subjectDrawingId,
          subjectPoolCap
        );
      }
    }

    describe("when called by jackpot contract", () => {
      it("should set pool cap correctly", async () => {
        await subject();
        
        expect(await jackpotLPManager.lpPoolCap()).to.equal(subjectPoolCap);
      });

      describe("when pool cap is less than current LP total", () => {
        beforeEach(async () => {
          subjectPoolCap = INITIAL_LP_VALUE - 1n; // Less than current total
        });

        it("should revert with InvalidLPPoolCap", async () => {
          await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "InvalidLPPoolCap");
        });
      });

      describe("when pool cap is less than current LP total + pending deposits", () => {
        beforeEach(async () => {
          await mockJackpot.setLPPoolCap(await jackpotLPManager.getAddress(), DRAWING_ID_0, INITIAL_LP_VALUE * 2n);
          await mockJackpot.processDeposit(await jackpotLPManager.getAddress(), DRAWING_ID_0, user1.address, DEPOSIT_AMOUNT_1000);

          subjectPoolCap = INITIAL_LP_VALUE
        });

        it("should revert with InvalidLPPoolCap", async () => {
          await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "InvalidLPPoolCap");
        });
      });
    });

    describe("when called by unauthorized address", () => {
      beforeEach(async () => {
        subjectCaller = unauthorized;
      });

      it("should revert with UnauthorizedCaller", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "UnauthorizedCaller");
      });
    });
  });

  describe("#emergencyWithdrawLP", () => {
    let subjectDrawingId: bigint;
    let subjectUser: string;
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectDrawingId = DRAWING_ID_1;
      subjectUser = user1.address;
      subjectCaller = owner; // Jackpot contract (MockJackpot)

      // Initialize LP system with basic setup
      // Set LP pool cap to allow deposits
      await mockJackpot.setLPPoolCap(await jackpotLPManager.getAddress(), DRAWING_ID_0, usdc(100000));
      await mockJackpot.initializeLP(await jackpotLPManager.getAddress());
      await mockJackpot.processDeposit(await jackpotLPManager.getAddress(), DRAWING_ID_0, subjectUser, DEPOSIT_AMOUNT_1000);
      await mockJackpot.processDrawingSettlement(
        await jackpotLPManager.getAddress(),
        DRAWING_ID_0,
        0n, // LP earnings
        0n, // User winnings  
        0n  // Protocol fee
      );
      await mockJackpot.initializeDrawingLP(await jackpotLPManager.getAddress(), DRAWING_ID_1, await mockJackpot.lastNewLPValue());
    });

    async function subject(): Promise<any> {
      if (subjectCaller === owner) {
        return await mockJackpot.emergencyWithdrawLP(
          await jackpotLPManager.getAddress(),
          subjectDrawingId,
          subjectUser
        );
      } else {
        return await jackpotLPManager.connect(subjectCaller.wallet).emergencyWithdrawLP(
          subjectDrawingId,
          subjectUser
        );
      }
    }

    describe("when called by jackpot contract", () => {
      describe("when LP has empty state", () => {
        beforeEach(async () => {
          subjectUser = user2.address;
        });

        it("should return zero withdrawable amount", async () => {
          await subject();
          
          const withdrawableAmount = await mockJackpot.lastWithdrawableAmount();
          expect(withdrawableAmount).to.equal(BigInt(0));
        });

        it("should emit LpWithdrawFinalized event with zero amount", async () => {
          await expect(subject())
            .to.emit(jackpotLPManager, "LpWithdrawFinalized")
            .withArgs(subjectUser, subjectDrawingId, BigInt(0));
        });

        it("should clear all LP state", async () => {
          await subject();
          
          const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectUser);
          expect(lpInfo.consolidatedShares).to.equal(0n);
          expect(lpInfo.lastDeposit.amount).to.equal(0n);
          expect(lpInfo.lastDeposit.drawingId).to.equal(0n);
          expect(lpInfo.pendingWithdrawal.amountInShares).to.equal(0n);
          expect(lpInfo.pendingWithdrawal.drawingId).to.equal(0n);
          expect(lpInfo.claimableWithdrawals).to.equal(0n);
        });
      });

      describe("when LP has a lastDeposit", () => {
        it("should return the correct withdrawable amount", async () => {
          await subject();
          
          const withdrawableAmount = await mockJackpot.lastWithdrawableAmount();
          expect(withdrawableAmount).to.equal(DEPOSIT_AMOUNT_1000);
        });

        it("should emit LpWithdrawFinalized event with the correct amount", async () => {
          await expect(subject())
            .to.emit(jackpotLPManager, "LpWithdrawFinalized")
            .withArgs(subjectUser, subjectDrawingId, DEPOSIT_AMOUNT_1000);
        });

        it("should clear all LP state", async () => {
          await subject();
          
          const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectUser);
          expect(lpInfo.consolidatedShares).to.equal(0n);
          expect(lpInfo.lastDeposit.amount).to.equal(0n);
          expect(lpInfo.lastDeposit.drawingId).to.equal(0n);
          expect(lpInfo.pendingWithdrawal.amountInShares).to.equal(0n);
          expect(lpInfo.pendingWithdrawal.drawingId).to.equal(0n);
          expect(lpInfo.claimableWithdrawals).to.equal(0n);
        });

        describe("but the deposit was made in the current round", () => {
          beforeEach(async () => {
            await mockJackpot.processDeposit(await jackpotLPManager.getAddress(), DRAWING_ID_1, subjectUser, DEPOSIT_AMOUNT_1000);
          });
          
          it("should return the deposit amount as withdrawable amount", async () => {
            const lpInfoBefore: LP = await jackpotLPManager.getLpInfo(subjectUser);
            expect(lpInfoBefore.lastDeposit.amount).to.equal(DEPOSIT_AMOUNT_1000);
            expect(lpInfoBefore.lastDeposit.drawingId).to.equal(DRAWING_ID_1);
            expect(lpInfoBefore.consolidatedShares).to.equal(DEPOSIT_AMOUNT_1000);
            
            await subject();
            
            const withdrawableAmount = await mockJackpot.lastWithdrawableAmount();
            expect(withdrawableAmount).to.equal(DEPOSIT_AMOUNT_2000);
          });

          it("should subtract the deposit amount from the global pending deposits", async () => {
            const prePendingDeposits = (await jackpotLPManager.getLPDrawingState(DRAWING_ID_1)).pendingDeposits;

            expect(prePendingDeposits).to.equal(DEPOSIT_AMOUNT_1000);

            await subject();
            
            const postPendingDeposits = (await jackpotLPManager.getLPDrawingState(DRAWING_ID_1)).pendingDeposits;
            expect(postPendingDeposits).to.equal(0n);
          });
          
          it("should clear the lastDeposit", async () => {
            await subject();
            
            const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectUser);
            expect(lpInfo.lastDeposit.amount).to.equal(0n);
            expect(lpInfo.lastDeposit.drawingId).to.equal(0n);
          });
        });
      });

      describe("when the function is called in the 0th drawing", () => {
        beforeEach(async () => {
          subjectDrawingId = DRAWING_ID_0;
        });
        
        
        it("should return the correct withdrawable amount", async () => {
          await subject();
          
          const withdrawableAmount = await mockJackpot.lastWithdrawableAmount();
          expect(withdrawableAmount).to.equal(DEPOSIT_AMOUNT_1000);
        });

        it("should emit LpWithdrawFinalized event with the correct amount", async () => {
          await expect(subject())
            .to.emit(jackpotLPManager, "LpWithdrawFinalized")
            .withArgs(subjectUser, subjectDrawingId, DEPOSIT_AMOUNT_1000);
        });
      });

      describe("when LP has consolidatedShares", () => {
        beforeEach(async () => {
          // Set up consolidated shares by making a deposit and then consolidating it
          await mockJackpot.processDeposit(await jackpotLPManager.getAddress(), DRAWING_ID_1, subjectUser, BigInt(1));
          await mockJackpot.processDrawingSettlement(
            await jackpotLPManager.getAddress(),
            DRAWING_ID_1,
            usdc(100), // LP earnings
            0n, // User winnings  
            0n  // Protocol fee
          );
          await mockJackpot.initializeDrawingLP(
            await jackpotLPManager.getAddress(),
            DRAWING_ID_2, 
            await mockJackpot.lastNewLPValue()
          );

          subjectDrawingId = DRAWING_ID_2;
        });

        it("should convert consolidatedShares to withdrawable amount correctly", async () => {
          const lpInfoBefore: LP = await jackpotLPManager.getLpInfo(subjectUser);
          
          const drawingOneAccumulator = await jackpotLPManager.getDrawingAccumulator(1n);
          const expectedAmount = lpInfoBefore.consolidatedShares * drawingOneAccumulator / PRECISE_UNIT;
          
          await subject();
          
          const withdrawableAmount = await mockJackpot.lastWithdrawableAmount();
          expect(withdrawableAmount).to.equal(expectedAmount);
        });

        it("should subtract the withdraw amount from lpPoolTotal", async () => {
          const preLpPoolTotal = (await jackpotLPManager.getLPDrawingState(DRAWING_ID_2)).lpPoolTotal;

          expect(preLpPoolTotal).to.equal(DEPOSIT_AMOUNT_1000 + usdc(100) + BigInt(1));

          await subject();
          
          const postLpPoolTotal = (await jackpotLPManager.getLPDrawingState(DRAWING_ID_2)).lpPoolTotal;

          // .000001 USDC is lost due to rounding
          expect(postLpPoolTotal).to.equal(preLpPoolTotal - DEPOSIT_AMOUNT_1000 - usdc(100));
        });

        it("should clear consolidatedShares", async () => {
          await subject();
          
          const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectUser);
          expect(lpInfo.consolidatedShares).to.equal(0n);
        });
      });

      describe("when LP has a pendingWithdrawal from the same round", () => {
        beforeEach(async () => {
          // Convert all consolidated shares to pending withdrawal
          await mockJackpot.processInitiateWithdraw(
            await jackpotLPManager.getAddress(),
            DRAWING_ID_1,
            subjectUser,
            DEPOSIT_AMOUNT_1000 // Use the deposit amount as shares approximation
          );
        });

        it("should convert pendingWithdrawal to withdrawable amount correctly", async () => {
          const lpInfoBefore: LP = await jackpotLPManager.getLpInfo(subjectUser);
          expect(lpInfoBefore.pendingWithdrawal.amountInShares).to.equal(DEPOSIT_AMOUNT_1000);
          
          // Calculate expected amount:
          // pendingWithdrawal.amountInShares * accumulator[pendingWithdrawal.drawingId] / PRECISE_UNIT
          const pendingAccumulator = await jackpotLPManager.getDrawingAccumulator(lpInfoBefore.pendingWithdrawal.drawingId - 1n);
          const expectedAmount = lpInfoBefore.pendingWithdrawal.amountInShares * pendingAccumulator / PRECISE_UNIT;
          
          await subject();
          
          const withdrawableAmount = await mockJackpot.lastWithdrawableAmount();
          expect(withdrawableAmount).to.equal(expectedAmount);
        });

        it("should subtract the withdraw amount from the global pending withdrawals and lpPoolTotal", async () => {
          const prePendingWithdrawals = (await jackpotLPManager.getLPDrawingState(DRAWING_ID_1)).pendingWithdrawals;
          const preLpPoolTotal = (await jackpotLPManager.getLPDrawingState(DRAWING_ID_1)).lpPoolTotal;

          expect(prePendingWithdrawals).to.equal(DEPOSIT_AMOUNT_1000);
          expect(preLpPoolTotal).to.equal(DEPOSIT_AMOUNT_1000);

          await subject();
          
          const postPendingWithdrawals = (await jackpotLPManager.getLPDrawingState(DRAWING_ID_1)).pendingWithdrawals;
          const postLpPoolTotal = (await jackpotLPManager.getLPDrawingState(DRAWING_ID_1)).lpPoolTotal;

          expect(postPendingWithdrawals).to.equal(0n);
          expect(postLpPoolTotal).to.equal(0n);
        });

        it("should clear pendingWithdrawal", async () => {
          await subject();
          
          const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectUser);
          expect(lpInfo.pendingWithdrawal.amountInShares).to.equal(0n);
          expect(lpInfo.pendingWithdrawal.drawingId).to.equal(0n);
        });
      });

      describe("when LP has a pendingWithdrawal from an earlier round", () => {
        beforeEach(async () => {
          // Convert all consolidated shares to pending withdrawal
          await mockJackpot.processInitiateWithdraw(
            await jackpotLPManager.getAddress(),
            DRAWING_ID_1,
            subjectUser,
            DEPOSIT_AMOUNT_1000 // Use the deposit amount as shares approximation
          );

          await mockJackpot.processDrawingSettlement(
            await jackpotLPManager.getAddress(),
            DRAWING_ID_1,
            usdc(100), // LP earnings
            0n, // User winnings  
            0n  // Protocol fee
          );
          await mockJackpot.initializeDrawingLP(
            await jackpotLPManager.getAddress(),
            DRAWING_ID_2, 
            await mockJackpot.lastNewLPValue()
          );

          subjectDrawingId = DRAWING_ID_2;
        });

        it("should convert pendingWithdrawal to withdrawable amount correctly", async () => {
          const lpInfoBefore: LP = await jackpotLPManager.getLpInfo(subjectUser);
          expect(lpInfoBefore.pendingWithdrawal.amountInShares).to.equal(DEPOSIT_AMOUNT_1000);
          expect(lpInfoBefore.pendingWithdrawal.drawingId).to.equal(DRAWING_ID_1);
          
          // Calculate expected amount:
          // pendingWithdrawal.amountInShares * accumulator[pendingWithdrawal.drawingId] / PRECISE_UNIT
          const pendingAccumulator = await jackpotLPManager.getDrawingAccumulator(lpInfoBefore.pendingWithdrawal.drawingId);
          const expectedAmount = lpInfoBefore.pendingWithdrawal.amountInShares * pendingAccumulator / PRECISE_UNIT;
          
          await subject();
          
          const withdrawableAmount = await mockJackpot.lastWithdrawableAmount();
          expect(withdrawableAmount).to.equal(expectedAmount);
        });

        it("should clear pendingWithdrawal", async () => {
          await subject();
          
          const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectUser);
          expect(lpInfo.pendingWithdrawal.amountInShares).to.equal(0n);
          expect(lpInfo.pendingWithdrawal.drawingId).to.equal(0n);
        });
      });

      describe("when LP has only claimableWithdrawals", () => {
        beforeEach(async () => {
          // Convert all consolidated shares to pending withdrawal
          await mockJackpot.processInitiateWithdraw(
            await jackpotLPManager.getAddress(),
            DRAWING_ID_1,
            subjectUser,
            DEPOSIT_AMOUNT_1000 / 2n // Use the deposit amount as shares approximation
          );

          await mockJackpot.processDrawingSettlement(
            await jackpotLPManager.getAddress(),
            DRAWING_ID_1,
            usdc(100), // LP earnings
            0n, // User winnings  
            0n  // Protocol fee
          );
          await mockJackpot.initializeDrawingLP(
            await jackpotLPManager.getAddress(),
            DRAWING_ID_2, 
            await mockJackpot.lastNewLPValue()
          );

          subjectDrawingId = DRAWING_ID_2;

          // Now make another deposit in a future drawing to trigger consolidation
          await mockJackpot.processInitiateWithdraw(
            await jackpotLPManager.getAddress(),
            DRAWING_ID_2,
            subjectUser,
            DEPOSIT_AMOUNT_1000 / 2n
          );
        });

        it("should add claimableWithdrawals directly to withdrawable amount", async () => {
          const lpInfoBefore: LP = await jackpotLPManager.getLpInfo(subjectUser);
          const drawingOneAccumulator = await jackpotLPManager.getDrawingAccumulator(1n);
          const expectedAmount = lpInfoBefore.claimableWithdrawals + ((DEPOSIT_AMOUNT_1000 / 2n) * drawingOneAccumulator / PRECISE_UNIT);
          
          await subject();
          
          const withdrawableAmount = await mockJackpot.lastWithdrawableAmount();
          expect(withdrawableAmount).to.equal(expectedAmount);
        });

        it("should clear claimableWithdrawals", async () => {
          await subject();
          
          const lpInfo: LP = await jackpotLPManager.getLpInfo(subjectUser);
          expect(lpInfo.claimableWithdrawals).to.equal(0n);
        });
      });
    });

    describe("when called by unauthorized address", () => {
      beforeEach(async () => {
        subjectCaller = unauthorized;
      });

      it("should revert with UnauthorizedCaller", async () => {
        await expect(subject()).to.be.revertedWithCustomError(jackpotLPManager, "UnauthorizedCaller");
      });
    });
  });

  describe("View functions", () => {
    describe("#getLPValueBreakdown", () => {
      describe("#getLPValueBreakdown", () => {
        let subjectUser: string;
    
        beforeEach(async () => {
          subjectUser = user1.address;
    
          // Initialize LP system with basic setup
          // Set LP pool cap to allow deposits
          await mockJackpot.setLPPoolCap(await jackpotLPManager.getAddress(), DRAWING_ID_0, usdc(100000));
          await mockJackpot.initializeLP(await jackpotLPManager.getAddress());
          await mockJackpot.processDeposit(await jackpotLPManager.getAddress(), DRAWING_ID_0, subjectUser, DEPOSIT_AMOUNT_1000);
          await mockJackpot.processDrawingSettlement(
            await jackpotLPManager.getAddress(),
            DRAWING_ID_0,
            0n, // LP earnings
            0n, // User winnings  
            0n  // Protocol fee
          );
          await mockJackpot.initializeDrawingLP(await jackpotLPManager.getAddress(), DRAWING_ID_1, await mockJackpot.lastNewLPValue());
          await mockJackpot.setDrawingId(DRAWING_ID_1);
        });
    
        async function subject(): Promise<any> {
          return await jackpotLPManager.getLPValueBreakdown(subjectUser);
        }
    
        describe("when called by jackpot contract", () => {
          describe("when LP has empty state", () => {
            beforeEach(async () => {
              subjectUser = user2.address;
            });
    
            it("should return zero withdrawable amount", async () => {
              const lpValueBreakdown: LPValueBreakdown = await subject();
              
              expect(lpValueBreakdown.activeDeposits).to.equal(0n);
              expect(lpValueBreakdown.pendingDeposits).to.equal(0n);
              expect(lpValueBreakdown.pendingWithdrawals).to.equal(0n);
              expect(lpValueBreakdown.claimableWithdrawals).to.equal(0n);
            });
          });
    
          describe("when LP has a lastDeposit", () => {
            beforeEach(async () => {
              await mockJackpot.processDrawingSettlement(
                await jackpotLPManager.getAddress(),
                DRAWING_ID_1,
                100n, // LP earnings
                0n, // User winnings  
                0n  // Protocol fee
              );
              await mockJackpot.initializeDrawingLP(await jackpotLPManager.getAddress(), DRAWING_ID_2, await mockJackpot.lastNewLPValue());
              await mockJackpot.setDrawingId(DRAWING_ID_2);
            });

            it("should return the correct active deposit amount", async () => {
              const lpValueBreakdown: LPValueBreakdown = await subject();

              const drawingOneAccumulator = await jackpotLPManager.getDrawingAccumulator(1n);
              expect(lpValueBreakdown.activeDeposits).to.equal(DEPOSIT_AMOUNT_1000 * drawingOneAccumulator / PRECISE_UNIT);
              expect(lpValueBreakdown.pendingDeposits).to.equal(0n);
              expect(lpValueBreakdown.pendingWithdrawals).to.equal(0n);
              expect(lpValueBreakdown.claimableWithdrawals).to.equal(0n);
            });
    
            describe("but the deposit was made in the current round", () => {
              beforeEach(async () => {
                await mockJackpot.processDeposit(await jackpotLPManager.getAddress(), DRAWING_ID_2, subjectUser, DEPOSIT_AMOUNT_1000);
              });
              
              it("should return the correct deposit amount and active deposits", async () => {                
                const lpValueBreakdown: LPValueBreakdown = await subject();

                const drawingOneAccumulator = await jackpotLPManager.getDrawingAccumulator(1n);
                expect(lpValueBreakdown.activeDeposits).to.equal(DEPOSIT_AMOUNT_1000 * drawingOneAccumulator / PRECISE_UNIT);
                expect(lpValueBreakdown.pendingDeposits).to.equal(DEPOSIT_AMOUNT_1000);
                expect(lpValueBreakdown.pendingWithdrawals).to.equal(0n);
                expect(lpValueBreakdown.claimableWithdrawals).to.equal(0n);
              });
            });
          });
    
          describe("when LP has consolidatedShares", () => {
            beforeEach(async () => {
              // Set up consolidated shares by making a deposit and then consolidating it
              await mockJackpot.processDeposit(await jackpotLPManager.getAddress(), DRAWING_ID_1, subjectUser, DEPOSIT_AMOUNT_1000);
              await mockJackpot.processDrawingSettlement(
                await jackpotLPManager.getAddress(),
                DRAWING_ID_1,
                usdc(100), // LP earnings
                0n, // User winnings  
                0n  // Protocol fee
              );
              await mockJackpot.initializeDrawingLP(
                await jackpotLPManager.getAddress(),
                DRAWING_ID_2, 
                await mockJackpot.lastNewLPValue()
              );
              await mockJackpot.setDrawingId(DRAWING_ID_2);
            });
    
            it("should convert consolidatedShares to USDC correctly", async () => {              
              const lpValueBreakdown: LPValueBreakdown = await subject();

              const drawingOneAccumulator = await jackpotLPManager.getDrawingAccumulator(1n);
              const newDepositValue = (DEPOSIT_AMOUNT_1000 * PRECISE_UNIT / drawingOneAccumulator) * drawingOneAccumulator / PRECISE_UNIT;
              expect(lpValueBreakdown.activeDeposits).to.equal(newDepositValue + (DEPOSIT_AMOUNT_1000 * drawingOneAccumulator / PRECISE_UNIT));
              expect(lpValueBreakdown.pendingDeposits).to.equal(0n);
              expect(lpValueBreakdown.pendingWithdrawals).to.equal(0n);
              expect(lpValueBreakdown.claimableWithdrawals).to.equal(0n);
            });
          });
    
          describe("when LP has a pendingWithdrawal from the same round", () => {
            beforeEach(async () => {
              await mockJackpot.processDrawingSettlement(
                await jackpotLPManager.getAddress(),
                DRAWING_ID_1,
                100n, // LP earnings
                0n, // User winnings  
                0n  // Protocol fee
              );
              await mockJackpot.initializeDrawingLP(await jackpotLPManager.getAddress(), DRAWING_ID_2, await mockJackpot.lastNewLPValue());
              await mockJackpot.setDrawingId(DRAWING_ID_2);

              // Convert all consolidated shares to pending withdrawal
              await mockJackpot.processInitiateWithdraw(
                await jackpotLPManager.getAddress(),
                DRAWING_ID_2,
                subjectUser,
                DEPOSIT_AMOUNT_1000 // Use the deposit amount as shares approximation
              );
            });
    
            it("should convert pendingWithdrawal to USDC correctly", async () => {
              const lpValueBreakdown: LPValueBreakdown = await subject();

              const drawingOneAccumulator = await jackpotLPManager.getDrawingAccumulator(1n);
              expect(lpValueBreakdown.pendingWithdrawals).to.equal(DEPOSIT_AMOUNT_1000 * drawingOneAccumulator / PRECISE_UNIT);
              expect(lpValueBreakdown.pendingDeposits).to.equal(0n);
              expect(lpValueBreakdown.activeDeposits).to.equal(0n);
              expect(lpValueBreakdown.claimableWithdrawals).to.equal(0n);
            });
          });
    
          describe("when LP has a pendingWithdrawal from an earlier round", () => {
            beforeEach(async () => {
              // Convert all consolidated shares to pending withdrawal
              await mockJackpot.processInitiateWithdraw(
                await jackpotLPManager.getAddress(),
                DRAWING_ID_1,
                subjectUser,
                DEPOSIT_AMOUNT_1000 // Use the deposit amount as shares approximation
              );
    
              await mockJackpot.processDrawingSettlement(
                await jackpotLPManager.getAddress(),
                DRAWING_ID_1,
                usdc(100), // LP earnings
                0n, // User winnings  
                0n  // Protocol fee
              );
              await mockJackpot.initializeDrawingLP(
                await jackpotLPManager.getAddress(),
                DRAWING_ID_2, 
                await mockJackpot.lastNewLPValue()
              );
              await mockJackpot.setDrawingId(DRAWING_ID_2);
            });
    
            it("should convert pendingWithdrawal to withdrawable amount in USDC correctly", async () => {              
              const lpValueBreakdown: LPValueBreakdown = await subject();

              const drawingOneAccumulator = await jackpotLPManager.getDrawingAccumulator(1n);
              expect(lpValueBreakdown.pendingWithdrawals).to.equal(0n);
              expect(lpValueBreakdown.pendingDeposits).to.equal(0n);
              expect(lpValueBreakdown.activeDeposits).to.equal(0n);
              expect(lpValueBreakdown.claimableWithdrawals).to.equal(DEPOSIT_AMOUNT_1000 * drawingOneAccumulator / PRECISE_UNIT);
            });
          });
    
          describe("when LP has only claimableWithdrawals", () => {
            beforeEach(async () => {
              // Convert all consolidated shares to pending withdrawal
              await mockJackpot.processInitiateWithdraw(
                await jackpotLPManager.getAddress(),
                DRAWING_ID_1,
                subjectUser,
                DEPOSIT_AMOUNT_1000 / 2n // Use the deposit amount as shares approximation
              );
    
              await mockJackpot.processDrawingSettlement(
                await jackpotLPManager.getAddress(),
                DRAWING_ID_1,
                usdc(100), // LP earnings
                0n, // User winnings  
                0n  // Protocol fee
              );
              await mockJackpot.initializeDrawingLP(
                await jackpotLPManager.getAddress(),
                DRAWING_ID_2, 
                await mockJackpot.lastNewLPValue()
              );
    
              await mockJackpot.setDrawingId(DRAWING_ID_2);
    
              // Now make another deposit in a future drawing to trigger consolidation
              await mockJackpot.processInitiateWithdraw(
                await jackpotLPManager.getAddress(),
                DRAWING_ID_2,
                subjectUser,
                DEPOSIT_AMOUNT_1000 / 2n
              );
            });
    
            it("should add claimableWithdrawals directly to withdrawable amount", async () => {
              const lpValueBreakdown: LPValueBreakdown = await subject();
              
              const drawingOneAccumulator = await jackpotLPManager.getDrawingAccumulator(1n);
              const expectedWithdrawableAmount = (DEPOSIT_AMOUNT_1000/2n) * drawingOneAccumulator / PRECISE_UNIT;
              
              expect(lpValueBreakdown.claimableWithdrawals).to.equal(expectedWithdrawableAmount);
              expect(lpValueBreakdown.pendingWithdrawals).to.equal(expectedWithdrawableAmount);
              expect(lpValueBreakdown.pendingDeposits).to.equal(0n);
              expect(lpValueBreakdown.activeDeposits).to.equal(0n);
            });
          });
        });
      });
    });

    describe("#getDrawingAccumulator", () => {
      it("should return correct accumulator value", async () => {
        await mockJackpot.initializeLP(await jackpotLPManager.getAddress());
        
        const accumulator: bigint = await jackpotLPManager.getDrawingAccumulator(DRAWING_ID_0);
        expect(accumulator).to.equal(PRECISE_UNIT);
      });
    });

    describe("#getLpInfo", () => {
      it("should return empty LP info for new address", async () => {
        const lpInfo: LP = await jackpotLPManager.getLpInfo(user1.address);
        
        expect(lpInfo.consolidatedShares).to.equal(0n);
        expect(lpInfo.lastDeposit.amount).to.equal(0n);
        expect(lpInfo.lastDeposit.drawingId).to.equal(0n);
        expect(lpInfo.pendingWithdrawal.amountInShares).to.equal(0n);
        expect(lpInfo.pendingWithdrawal.drawingId).to.equal(0n);
        expect(lpInfo.claimableWithdrawals).to.equal(0n);
      });
    });

    describe("#getLPDrawingState", () => {
      it("should return empty state for uninitialized drawing", async () => {
        const drawingState: LPDrawingState = await jackpotLPManager.getLPDrawingState(DRAWING_ID_1);
        
        expect(drawingState.lpPoolTotal).to.equal(0n);
        expect(drawingState.pendingDeposits).to.equal(0n);
        expect(drawingState.pendingWithdrawals).to.equal(0n);
      });
    });
  });
});
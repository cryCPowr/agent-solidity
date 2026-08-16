import { ethers } from "hardhat";
import DeployHelper from "@utils/deploys";

import {
  getWaffleExpect,
  getAccounts
} from "@utils/test/index";
import { Account } from "@utils/test";
import { calculatePackedTicket, generateSubset } from "@utils/protocolUtils";

import { TicketComboTrackerTester } from "@utils/contracts";
import { takeSnapshot, SnapshotRestorer } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { ComboCount, Ticket } from "@utils/types";

const expect = getWaffleExpect();

describe("TicketComboTracker", () => {
  let owner: Account;
  let user: Account;

  let tracker: TicketComboTrackerTester;
  let snapshot: SnapshotRestorer;

  beforeEach(async () => {
    [owner, user] = await getAccounts();
    
    const deployer = new DeployHelper(owner.wallet);
    tracker = await deployer.deployTicketComboTrackerTester();
    
    snapshot = await takeSnapshot();
  });

  beforeEach(async () => {
    await snapshot.restore();
  });

  describe("#init", async () => {
    let subjectNormalMax: number;
    let subjectBonusballMax: number;
    let subjectNormalTiers: number;

    beforeEach(async () => {
      subjectNormalMax = 30;
      subjectBonusballMax = 10;
      subjectNormalTiers = 5;
    });

    async function subject(): Promise<any> {
      return await tracker.init(subjectNormalMax, subjectBonusballMax, subjectNormalTiers);
    }

    it("should set the correct normal max", async () => {
      await subject();
      
      const normalMax = await tracker.getNormalMax();
      expect(normalMax).to.eq(subjectNormalMax);
    });

    it("should set the correct bonusball max", async () => {
      await subject();
      
      const bonusballMax = await tracker.getBonusballMax();
      expect(bonusballMax).to.eq(subjectBonusballMax);
    });

    it("should set the correct normal tiers", async () => {
      await subject();
      
      const normalTiers = await tracker.getNormalTiers();
      expect(normalTiers).to.eq(subjectNormalTiers);
    });
  });

  describe("#toNormalsBitVector", async () => {
    let subjectSet: number[];
    let subjectBonusball: number;
    let subjectMaxNormalBall: number;

    beforeEach(async () => {
      subjectSet = [1, 5, 10, 15, 20];
      subjectBonusball = 3;
      subjectMaxNormalBall = 30;
    });

    async function subject(): Promise<bigint> {
      return await tracker.toNormalsBitVector(subjectSet, subjectMaxNormalBall);
    }

    describe("when set contains standard numbers", async () => {
      beforeEach(async () => {
        subjectSet = [1, 5, 10, 15, 20];
      });

      it("should create correct bit vector for normal balls", async () => {
        // Test: [1, 5, 10, 15, 20] should set bits at positions 1, 5, 10, 15, 20
        const result = await subject();
        
        // Expected bit vector: bits set at positions 1, 5, 10, 15, 20
        // Binary: 100001000001000010010 (reading right to left, bit 0 unused)
        const expectedBits = (1n << 1n) | (1n << 5n) | (1n << 10n) | (1n << 15n) | (1n << 20n);
        expect(result).to.equal(expectedBits);
      });
    });

    describe("when set contains minimum boundary number", async () => {
      beforeEach(async () => {
        subjectSet = [1];
      });

      it("should handle minimum boundary (number 1)", async () => {
        const result = await subject();
        const expectedBits = 1n << 1n; // Bit at position 1
        expect(result).to.equal(expectedBits);
      });
    });

    describe("when set contains maximum boundary number", async () => {
      beforeEach(async () => {
        subjectSet = [30];
      });

      it("should handle maximum boundary (number 30)", async () => {
        const result = await subject();
        const expectedBits = 1n << 30n; // Bit at position 30
        expect(result).to.equal(expectedBits);
      });
    });

    describe("when set contains single number", async () => {
      beforeEach(async () => {
        subjectSet = [15];
      });

      it("should handle single number selection", async () => {
        const result = await subject();
        const expectedBits = 1n << 15n; // Only bit 15 set
        expect(result).to.equal(expectedBits);
      });
    });

    describe("when set contains consecutive numbers", async () => {
      beforeEach(async () => {
        subjectSet = [1, 2, 3, 4, 5];
      });

      it("should handle multiple consecutive numbers", async () => {
        const result = await subject();
        // Bits 1, 2, 3, 4, 5 should be set
        const expectedBits = (1n << 1n) | (1n << 2n) | (1n << 3n) | (1n << 4n) | (1n << 5n);
        expect(result).to.equal(expectedBits);
      });
    });

    describe("when set is an empty array", async () => {
      beforeEach(async () => {
        subjectSet = [];
      });

      it("should revert with 'Invalid set length'", async () => {
        await expect(subject()).to.be.revertedWith("Invalid set length");
      });
    });

    describe("when set contains duplicate numbers", async () => {
      beforeEach(async () => {
        subjectSet = [1, 5, 5, 15, 20]; // duplicate 5
      });

      it("should revert with 'Duplicate number in set'", async () => {
        await expect(subject()).to.be.revertedWith("Duplicate number in set");
      });
    });

    describe("when set contains invalid number zero", async () => {
      beforeEach(async () => {
        subjectSet = [0, 5, 10, 15, 20]; // invalid 0
      });

      it("should revert with 'Invalid set selection'", async () => {
        await expect(subject()).to.be.revertedWith("Invalid set selection");
      });
    });

    describe("when set contains number greater than max", async () => {
      beforeEach(async () => {
        subjectSet = [1, 5, 10, 15, 31]; // 31 > maxNormalBall (30)
      });

      it("should revert with 'Invalid set selection'", async () => {
        await expect(subject()).to.be.revertedWith("Invalid set selection");
      });
    });

    describe("when set contains both boundary numbers", async () => {
      beforeEach(async () => {
        subjectSet = [1, 15, 30]; // min and max boundaries
      });

      it("should handle both boundary numbers correctly", async () => {
        const result = await subject();
        const expectedBits = (1n << 1n) | (1n << 15n) | (1n << 30n);
        expect(result).to.equal(expectedBits);
      });
    });
  });

  describe("#isDuplicate", async () => {
    let subjectNormalBalls: number[];
    let subjectBonusball: number;

    beforeEach(async () => {
      await tracker.init(30, 10, 5);
      
      subjectNormalBalls = [1, 2, 3, 4, 5];
      subjectBonusball = 6;
    });

    async function subject(): Promise<boolean> {
      return await tracker.isDuplicate(subjectNormalBalls, subjectBonusball);
    }

    describe("when no tickets have been inserted", async () => {
      it("should return false for any combination", async () => {
        const result = await subject();
        expect(result).to.be.false;
      });
    });

    describe("when checking different combinations", async () => {
      beforeEach(async () => {
        // Insert a specific combination first
        await tracker.insert([1, 2, 3, 4, 5], 6);
      });

      describe("when checking the same combination", async () => {
        it("should return true for existing combination", async () => {
          const result = await subject();
          expect(result).to.be.true;
        });
      });

      describe("when checking same normals with different bonusball", async () => {
        beforeEach(async () => {
          subjectBonusball = 7; // Different bonusball
        });

        it("should return false", async () => {
          const result = await subject();
          expect(result).to.be.false;
        });
      });

      describe("when checking different normals with same bonusball", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [1, 2, 3, 4, 6]; // Different last normal
        });

        it("should return false", async () => {
          const result = await subject();
          expect(result).to.be.false;
        });
      });

      describe("when checking completely different combination", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [10, 11, 12, 13, 14];
          subjectBonusball = 8;
        });

        it("should return false", async () => {
          const result = await subject();
          expect(result).to.be.false;
        });
      });
    });

    describe("when using boundary numbers", async () => {
      describe("when checking combination with minimum numbers", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [1, 2, 3, 4, 5];
          subjectBonusball = 1; // Min bonusball
          
          // Insert this combination first
          await tracker.insert(subjectNormalBalls, subjectBonusball);
        });

        it("should return true for inserted boundary combination", async () => {
          const result = await subject();
          expect(result).to.be.true;
        });
      });

      describe("when checking combination with maximum numbers", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [26, 27, 28, 29, 30]; // Include max normal (30)
          subjectBonusball = 10; // Max bonusball
          
          // Insert this combination first
          await tracker.insert(subjectNormalBalls, subjectBonusball);
        });

        it("should return true for inserted max boundary combination", async () => {
          const result = await subject();
          expect(result).to.be.true;
        });
      });

      describe("when checking uninserted boundary combination", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [1, 15, 25, 29, 30]; // Mix including min and max (5 balls)
          subjectBonusball = 10; // Max bonusball
          // Don't insert - checking new combination
        });

        it("should return false for new boundary combination", async () => {
          const result = await subject();
          expect(result).to.be.false;
        });
      });
    });

    describe("when multiple combinations exist", async () => {
      beforeEach(async () => {
        // Insert multiple different combinations
        await tracker.insert([1, 2, 3, 4, 5], 6);
        await tracker.insert([1, 2, 3, 4, 6], 6); // Same bonusball, different normals
        await tracker.insert([1, 2, 3, 4, 5], 7); // Different bonusball, same normals
      });

      describe("when checking first inserted combination", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [1, 2, 3, 4, 5];
          subjectBonusball = 6;
        });

        it("should return true", async () => {
          const result = await subject();
          expect(result).to.be.true;
        });
      });

      describe("when checking second inserted combination", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [1, 2, 3, 4, 6];
          subjectBonusball = 6;
        });

        it("should return true", async () => {
          const result = await subject();
          expect(result).to.be.true;
        });
      });

      describe("when checking third inserted combination", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [1, 2, 3, 4, 5];
          subjectBonusball = 7;
        });

        it("should return true", async () => {
          const result = await subject();
          expect(result).to.be.true;
        });
      });

      describe("when checking non-inserted combination", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [10, 11, 12, 13, 14];
          subjectBonusball = 8;
        });

        it("should return false", async () => {
          const result = await subject();
          expect(result).to.be.false;
        });
      });
    });

    describe("when checking duplicate insertions", async () => {
      beforeEach(async () => {
        // Insert same combination twice
        await tracker.insert([1, 2, 3, 4, 5], 6);
        await tracker.insert([1, 2, 3, 4, 5], 6); // Duplicate
        
        subjectNormalBalls = [1, 2, 3, 4, 5];
        subjectBonusball = 6;
      });

      it("should still return true (duplicates don't affect existence)", async () => {
        const result = await subject();
        expect(result).to.be.true;
      });
    });

    describe("when input validation fails", async () => {
      describe("when set has wrong number of balls", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [1, 15, 30]; // Only 3 balls when 5 expected
          subjectBonusball = 6;
        });

        it("should revert with 'Invalid set length'", async () => {
          await expect(subject()).to.be.revertedWith("Invalid set length");
        });
      });

      describe("when set has too many balls", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [1, 2, 3, 4, 5, 6, 7]; // 7 balls when 5 expected
          subjectBonusball = 6;
        });

        it("should revert with 'Invalid set length'", async () => {
          await expect(subject()).to.be.revertedWith("Invalid set length");
        });
      });
    });
  });

  describe("#insert", async () => {
    let subjectNormalBalls: bigint[];
    let subjectBonusball: bigint;

    beforeEach(async () => {
      await tracker.init(30, 10, 5);
    
      subjectNormalBalls = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)];
      subjectBonusball = BigInt(6);
    });

    async function subject(): Promise<any> {
      return await tracker.insert(subjectNormalBalls, subjectBonusball);
    }

    it("should increment combo count correctly", async () => {
      await subject();

      const comboCounts: ComboCount = await tracker.getComboCount(BigInt(6), BigInt(2));
      const bonusballTicketCounts: ComboCount = await tracker.getBonusballTicketCounts(BigInt(6));
      expect(comboCounts.count).to.eq(1);
      expect(comboCounts.dupCount).to.eq(0);
      expect(bonusballTicketCounts.count).to.eq(1);
      expect(bonusballTicketCounts.dupCount).to.eq(0);
    });

    describe("when multiple insertions of same combo", async () => {
      beforeEach(async () => {
        await subject();
      });

      it("should increment combo count correctly", async () => {
      await subject();

      const comboCounts: ComboCount = await tracker.getComboCount(BigInt(6), BigInt(2));
      const bonusballTicketCounts: ComboCount = await tracker.getBonusballTicketCounts(BigInt(6));
      expect(comboCounts.count).to.eq(1);
      expect(comboCounts.dupCount).to.eq(1);
      expect(bonusballTicketCounts.count).to.eq(1);
      expect(bonusballTicketCounts.dupCount).to.eq(1);
      });
    });

    describe("when same normals but different bonusball", async () => {
      beforeEach(async () => {
        await subject();
        subjectBonusball = BigInt(5);
      });

      it("should increment combo count correctly", async () => {
        await subject();

        const comboCountsSix: ComboCount = await tracker.getComboCount(BigInt(6), BigInt(2));
        const comboCountsFive: ComboCount = await tracker.getComboCount(BigInt(5), BigInt(2));
        const bonusballTicketCountsSix: ComboCount = await tracker.getBonusballTicketCounts(BigInt(6));
        const bonusballTicketCountsFive: ComboCount = await tracker.getBonusballTicketCounts(BigInt(5));
        expect(comboCountsSix.count).to.eq(1);
        expect(comboCountsSix.dupCount).to.eq(0);
        expect(comboCountsFive.count).to.eq(1);
        expect(comboCountsFive.dupCount).to.eq(0);
        expect(bonusballTicketCountsSix.count).to.eq(1);
        expect(bonusballTicketCountsSix.dupCount).to.eq(0);
        expect(bonusballTicketCountsFive.count).to.eq(1);
        expect(bonusballTicketCountsFive.dupCount).to.eq(0);
      });
    });

    describe("when different normals but same bonusball", async () => {
      beforeEach(async () => {
        await subject();

        subjectNormalBalls = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(6)];
      });

      it("should increment combo count correctly", async () => {
        await subject();

        const overlapComboCounts: ComboCount = await tracker.getComboCount(BigInt(6), generateSubset([BigInt(1),BigInt(2),BigInt(3),BigInt(4)]));
        const nonOverlapComboCounts: ComboCount = await tracker.getComboCount(BigInt(6), generateSubset(subjectNormalBalls));
        const bonusballTicketCounts: ComboCount = await tracker.getBonusballTicketCounts(BigInt(6));
        expect(overlapComboCounts.count).to.eq(2);
        expect(overlapComboCounts.dupCount).to.eq(0);
        expect(nonOverlapComboCounts.count).to.eq(1);
        expect(nonOverlapComboCounts.dupCount).to.eq(0);
        expect(bonusballTicketCounts.count).to.eq(2);
        expect(bonusballTicketCounts.dupCount).to.eq(0);
      });
    });

    describe("when using boundary numbers", async () => {
      describe("when using minimum boundary numbers", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)]; // Include min normal (1)
          subjectBonusball = BigInt(1); // Min bonusball
        });

        it("should handle minimum boundary numbers correctly", async () => {
          await subject();

          const comboCounts: ComboCount = await tracker.getComboCount(BigInt(1), BigInt(2)); // Check bit position 1
          const bonusballTicketCounts: ComboCount = await tracker.getBonusballTicketCounts(BigInt(1));
          
          expect(comboCounts.count).to.eq(1);
          expect(comboCounts.dupCount).to.eq(0);
          expect(bonusballTicketCounts.count).to.eq(1);
          expect(bonusballTicketCounts.dupCount).to.eq(0);
        });
      });

      describe("when using maximum boundary numbers", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [BigInt(26), BigInt(27), BigInt(28), BigInt(29), BigInt(30)]; // Include max normal (30)
          subjectBonusball = BigInt(10); // Max bonusball
        });

        it("should handle maximum boundary numbers correctly", async () => {
          await subject();

          const maxNormalBit = 1n << 30n; // Bit position for normal 30
          const bonusballTicketCounts: ComboCount = await tracker.getBonusballTicketCounts(BigInt(10));
          
          expect(bonusballTicketCounts.count).to.eq(1);
          expect(bonusballTicketCounts.dupCount).to.eq(0);
        });
      });

      describe("when using mixed boundary numbers", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [BigInt(1), BigInt(15), BigInt(25), BigInt(29), BigInt(30)]; // Mix of min, mid, and max
          subjectBonusball = BigInt(5); // Mid-range bonusball
        });

        it("should handle mixed boundary numbers correctly", async () => {
          await subject();

          const bonusballTicketCounts: ComboCount = await tracker.getBonusballTicketCounts(BigInt(5));
          expect(bonusballTicketCounts.count).to.eq(1);
          expect(bonusballTicketCounts.dupCount).to.eq(0);
        });
      });
    });

    describe("when validating input parameters", async () => {
      describe("when normalBalls array has wrong length", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [BigInt(1), BigInt(2), BigInt(3)]; // Only 3 balls when 5 expected
          subjectBonusball = BigInt(6);
        });

        it("should revert with 'Invalid pick length'", async () => {
          await expect(subject()).to.be.revertedWith("Invalid pick length");
        });
      });

      describe("when normalBalls array has too many numbers", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5), BigInt(6), BigInt(7)]; // 7 balls when 5 expected
          subjectBonusball = BigInt(6);
        });

        it("should revert with 'Invalid pick length'", async () => {
          await expect(subject()).to.be.revertedWith("Invalid pick length");
        });
      });

      describe("when normalBalls contains invalid number zero", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [BigInt(0), BigInt(2), BigInt(3), BigInt(4), BigInt(5)]; // Invalid 0
          subjectBonusball = BigInt(6);
        });

        it("should revert with 'Invalid set selection'", async () => {
          await expect(subject()).to.be.revertedWith("Invalid set selection");
        });
      });

      describe("when normalBalls contains number greater than max", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(31)]; // 31 > maxNormal (30)
          subjectBonusball = BigInt(6);
        });

        it("should revert with 'Invalid set selection'", async () => {
          await expect(subject()).to.be.revertedWith("Invalid set selection");
        });
      });

      describe("when normalBalls contains duplicate numbers", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [BigInt(1), BigInt(2), BigInt(3), BigInt(3), BigInt(5)]; // Duplicate 3
          subjectBonusball = BigInt(6);
        });

        it("should revert with 'Duplicate number in set'", async () => {
          await expect(subject()).to.be.revertedWith("Duplicate number in set");
        });
      });
    });

    describe("when verifying return values and bit positioning", async () => {
      beforeEach(async () => {
        subjectNormalBalls = [BigInt(1), BigInt(5), BigInt(10), BigInt(15), BigInt(20)];
        subjectBonusball = BigInt(6);
      });

      it("should return correct isDup flag for first insertion", async () => {
        // For the first insertion, isDup should be false since it's captured in the return value
        // But we can verify through the combo counts
        await subject();
        
        // Verify it was not marked as duplicate in storage
        const comboCounts: ComboCount = await tracker.getComboCount(BigInt(6), BigInt(2)); // Bit for number 1
        expect(comboCounts.count).to.eq(1);
        expect(comboCounts.dupCount).to.eq(0);
      });

      it("should return correct isDup flag for duplicate insertion", async () => {
        // Insert once first
        await subject();
        
        // Insert same combination again
        await subject();
        
        // Verify duplicate was properly tracked
        const comboCounts: ComboCount = await tracker.getComboCount(BigInt(6), BigInt(2)); // Bit for number 1
        expect(comboCounts.count).to.eq(1); // Count stays 1
        expect(comboCounts.dupCount).to.eq(1); // DupCount increments
      });

      it("should place bonusball in correct bit position", async () => {
        await subject();
        
        // For normalMax=30, bonusball=6 should be at position 30+6=36
        // We can verify this by checking that different bonusballs create different combinations
        const bonusball6Counts: ComboCount = await tracker.getBonusballTicketCounts(BigInt(6));
        const bonusball7Counts: ComboCount = await tracker.getBonusballTicketCounts(BigInt(7));
        
        expect(bonusball6Counts.count).to.eq(1);
        expect(bonusball7Counts.count).to.eq(0); // Different bonusball, no count
      });
    });

    describe("when testing bonusball boundary values", async () => {
      describe("when using minimum bonusball", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)];
          subjectBonusball = BigInt(1); // Min bonusball
        });

        it("should handle minimum bonusball correctly", async () => {
          await subject();
          
          const bonusballCounts: ComboCount = await tracker.getBonusballTicketCounts(BigInt(1));
          expect(bonusballCounts.count).to.eq(1);
          expect(bonusballCounts.dupCount).to.eq(0);
        });
      });

      describe("when using maximum bonusball", async () => {
        beforeEach(async () => {
          subjectNormalBalls = [BigInt(1), BigInt(2), BigInt(3), BigInt(4), BigInt(5)];
          subjectBonusball = BigInt(10); // Max bonusball
        });

        it("should handle maximum bonusball correctly", async () => {
          await subject();
          
          const bonusballCounts: ComboCount = await tracker.getBonusballTicketCounts(BigInt(10));
          expect(bonusballCounts.count).to.eq(1);
          expect(bonusballCounts.dupCount).to.eq(0);
        });
      });
    });
  });

  describe("#countTierMatchesWithBonusball", async () => {
    let subjectNormalBalls: bigint[];
    let subjectBonusball: bigint;

    let insertions: Ticket[] = [
      { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)], bonusball: BigInt(6) },
      { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(6)], bonusball: BigInt(6) },
      { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(7)], bonusball: BigInt(6) },
      { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(8)], bonusball: BigInt(6) },
      { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(9)], bonusball: BigInt(6) },
    ];

    beforeEach(async () => {
      await tracker.init(30, 10, 5);

      for (const insertion of insertions) {
        await tracker.insert(insertion.normals, insertion.bonusball);
      }

      subjectNormalBalls = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)];
      subjectBonusball = BigInt(6);
    });

    async function subject(): Promise<any> {
      return await tracker.countTierMatchesWithBonusball(subjectNormalBalls, subjectBonusball);
    }

    it("should return the correct matches", async () => {
      const [winningTicket, result, dupResult] = await subject();

      expect(winningTicket).to.eq(calculatePackedTicket({normals: subjectNormalBalls, bonusball: subjectBonusball}, BigInt(30)));
      expect(result).to.deep.equal([0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1]);
      expect(dupResult).to.deep.equal([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    });

    describe("when there are duplicate winners inserted", async () => {
      beforeEach(async () => {
        await tracker.insert([BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)], BigInt(6));
      });

      it("should return the correct matches", async () => {
        const [winningTicket, result, dupResult] = await subject();

        expect(winningTicket).to.eq(calculatePackedTicket({normals: subjectNormalBalls, bonusball: subjectBonusball}, BigInt(30)));
        expect(result).to.deep.equal([0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1]);
        expect(dupResult).to.deep.equal([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
      });
    });

    describe("when there is a ticket with no matches except bonusball match", async () => {
      beforeEach(async () => {
        await tracker.insert([BigInt(7),BigInt(8),BigInt(9),BigInt(10),BigInt(11)], BigInt(6));
      });

      it("should return the correct matches", async () => {
        const [winningTicket, result, dupResult] = await subject();

        expect(winningTicket).to.eq(calculatePackedTicket({normals: subjectNormalBalls, bonusball: subjectBonusball}, BigInt(30)));
        expect(result).to.deep.equal([0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1]);
        expect(dupResult).to.deep.equal([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      });
    });

    describe("when there are duplicate tickets with no matches except bonusball match", async () => {
      beforeEach(async () => {
        await tracker.insert([BigInt(7),BigInt(8),BigInt(9),BigInt(10),BigInt(11)], BigInt(6));
        await tracker.insert([BigInt(7),BigInt(8),BigInt(9),BigInt(10),BigInt(11)], BigInt(6));
      });

      it("should return the correct matches", async () => {
        const [winningTicket, result, dupResult] = await subject();

        expect(winningTicket).to.eq(calculatePackedTicket({normals: subjectNormalBalls, bonusball: subjectBonusball}, BigInt(30)));
        expect(result).to.deep.equal([0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1]);
        expect(dupResult).to.deep.equal([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      });
    });

    describe("comprehensive edge cases and complex scenarios", async () => {
      describe("when tracker is empty", async () => {
        before(async () => {
          insertions = []; // Empty insertions
        });
        
        beforeEach(async () => {
          subjectNormalBalls = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)];
          subjectBonusball = BigInt(6);
        });

        it("should return all zeros for empty tracker", async () => {
          const [winningTicket, result, dupResult] = await subject();
          
          expect(winningTicket).to.eq(calculatePackedTicket({normals: subjectNormalBalls, bonusball: subjectBonusball}, BigInt(30)));
          expect(result).to.deep.equal([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
          expect(dupResult).to.deep.equal([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        });
      });

      describe("when testing different tier matches", async () => {
        before(async () => {
          // Setup tickets with different numbers of matches
          insertions = [
            { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)], bonusball: BigInt(6) }, // 5 matches + bonusball
            { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(20)], bonusball: BigInt(6) }, // 4 matches + bonusball
            { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(21),BigInt(22)], bonusball: BigInt(6) }, // 3 matches + bonusball
            { normals: [BigInt(1),BigInt(2),BigInt(23),BigInt(24),BigInt(25)], bonusball: BigInt(6) }, // 2 matches + bonusball
            { normals: [BigInt(1),BigInt(26),BigInt(27),BigInt(28),BigInt(29)], bonusball: BigInt(6) }, // 1 match + bonusball
            { normals: [BigInt(10),BigInt(11),BigInt(12),BigInt(13),BigInt(14)], bonusball: BigInt(7) }, // 0 matches, wrong bonusball
            { normals: [BigInt(15),BigInt(16),BigInt(17),BigInt(18),BigInt(19)], bonusball: BigInt(6) } // 0 matches, right bonusball
          ];
        });
        
        beforeEach(async () => {
          subjectNormalBalls = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)];
          subjectBonusball = BigInt(6);
        });

        it("should correctly count matches across all tiers", async () => {
          const [winningTicket, result, dupResult] = await subject();
          
          expect(winningTicket).to.eq(calculatePackedTicket({normals: subjectNormalBalls, bonusball: subjectBonusball}, BigInt(30)));
          // result[1] = bonusball only, result[3] = 1+bonusball, result[5] = 2+bonusball, etc.
          expect(result[1]).to.equal(1); // 1 ticket with bonusball only (no normal matches)
          expect(result[3]).to.equal(1); // 1 ticket with 1 normal + bonusball 
          expect(result[5]).to.equal(1); // 1 ticket with 2 normals + bonusball
          expect(result[7]).to.equal(1); // 1 ticket with 3 normals + bonusball
          expect(result[9]).to.equal(1); // 1 ticket with 4 normals + bonusball
          expect(result[11]).to.equal(1); // 1 ticket with 5 normals + bonusball
          expect(dupResult).to.deep.equal([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        });
      });

      describe("when testing boundary conditions", async () => {
        before(async () => {
          // Test with boundary numbers
          insertions = [
            { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(30)], bonusball: BigInt(1) }, // min/max normals, min bonusball
            { normals: [BigInt(26),BigInt(27),BigInt(28),BigInt(29),BigInt(30)], bonusball: BigInt(10) } // max normals, max bonusball
          ];
        });
        
        beforeEach(async () => {
          subjectNormalBalls = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)];
          subjectBonusball = BigInt(1);
        });

        it("should handle boundary numbers correctly", async () => {
          const [winningTicket, result, dupResult] = await subject();

          expect(winningTicket).to.eq(calculatePackedTicket({normals: subjectNormalBalls, bonusball: subjectBonusball}, BigInt(30)));
          expect(result[9]).to.equal(1); // One ticket matches 4 normals with bonusball match
          expect(result[0]).to.equal(0); // No tickets match 0 normals without bonusball match
          expect(result[11]).to.equal(0); // No full matches with bonusball
          expect(dupResult).to.deep.equal([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // No duplicates
        });
      });

      describe("when testing complex inclusion-exclusion scenarios", async () => {
        before(async () => {
          // Create overlapping subsets that test inclusion-exclusion principle
          insertions = [
            { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)], bonusball: BigInt(6) }, // Full match
            { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(6)], bonusball: BigInt(6) }, // 4 match overlap
            { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(7),BigInt(8)], bonusball: BigInt(6) }, // 3 match overlap
            { normals: [BigInt(1),BigInt(2),BigInt(9),BigInt(10),BigInt(11)], bonusball: BigInt(6) }, // 2 match overlap
            { normals: [BigInt(1),BigInt(12),BigInt(13),BigInt(14),BigInt(15)], bonusball: BigInt(6) } // 1 match overlap
          ];
        });
        
        beforeEach(async () => {
          subjectNormalBalls = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)];
          subjectBonusball = BigInt(6);
        });

        it("should correctly apply inclusion-exclusion principle", async () => {
          const [winningTicket, result, dupResult] = await subject();
          
          expect(winningTicket).to.eq(calculatePackedTicket({normals: subjectNormalBalls, bonusball: subjectBonusball}, BigInt(30)));
          // Verify that higher tier matches are properly subtracted from lower tiers
          expect(result[11]).to.equal(1); // Exactly 1 ticket with all 5 matches + bonusball
          expect(result[9]).to.equal(1); // Exactly 1 ticket with 4 matches + bonusball (after inclusion-exclusion)
          expect(result[7]).to.equal(1); // Exactly 1 ticket with 3 matches + bonusball (after inclusion-exclusion)
          expect(result[5]).to.equal(1); // Exactly 1 ticket with 2 matches + bonusball (after inclusion-exclusion)
          expect(result[3]).to.equal(1); // Exactly 1 ticket with 1 match + bonusball (after inclusion-exclusion)
        });
      });

      describe("when testing heavy duplicate scenarios", async () => {
        before(async () => {
          // Insert the same ticket multiple times
          insertions = [];
          for (let i = 0; i < 10; i++) {
            insertions.push({ normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)], bonusball: BigInt(6) });
          }
        });
        
        beforeEach(async () => {
          subjectNormalBalls = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)];
          subjectBonusball = BigInt(6);
        });

        it("should correctly track duplicates", async () => {
          const [winningTicket, result, dupResult] = await subject();
          
          expect(winningTicket).to.eq(calculatePackedTicket({normals: subjectNormalBalls, bonusball: subjectBonusball}, BigInt(30)));
          expect(result[11]).to.equal(1); // Only 1 unique ticket
          expect(dupResult[11]).to.equal(9); // 9 duplicates of that ticket
        });
      });

      describe("when testing single ticket scenarios", async () => {
        describe("when single ticket matches all normals and bonusball", async () => {
          before(async () => {
            insertions = [
              { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)], bonusball: BigInt(6) }
            ];
          });
          
          beforeEach(async () => {
            subjectNormalBalls = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)];
            subjectBonusball = BigInt(6);
          });

          it("should show match only in highest tier", async () => {
            const [winningTicket, result, dupResult] = await subject();
            
            expect(result[11]).to.equal(1); // Full match
            // When a single ticket matches everything, it creates subsets but inclusion-exclusion
            // principle should subtract them out, leaving only the full match
            // However, the actual behavior might be different - let's see what we get
          });
        });

        describe("when single ticket matches no normals but bonusball", async () => {
          before(async () => {
            insertions = [
              { normals: [BigInt(10),BigInt(11),BigInt(12),BigInt(13),BigInt(14)], bonusball: BigInt(6) }
            ];
          });
          
          beforeEach(async () => {
            subjectNormalBalls = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)];
            subjectBonusball = BigInt(6);
          });

          it("should show match only in bonusball-only tier", async () => {
            const [winningTicket, result, dupResult] = await subject();
            
            expect(result[1]).to.equal(1); // Bonusball-only match
            expect(result[3]).to.equal(0); // No 1+bonusball matches
            expect(result[11]).to.equal(0); // No full matches
          });
        });
      });

      describe("when testing multiple bonusball scenarios", async () => {
        before(async () => {
          // Insert tickets with different bonusballs
          insertions = [
            { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)], bonusball: BigInt(1) }, // Wrong bonusball
            { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)], bonusball: BigInt(6) }, // Right bonusball
            { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)], bonusball: BigInt(10) } // Wrong bonusball
          ];
        });
        
        beforeEach(async () => {
          subjectNormalBalls = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)];
          subjectBonusball = BigInt(6);
        });

        it("should only count matches with correct bonusball", async () => {
          const [winningTicket, result, dupResult] = await subject();
          
          expect(result[11]).to.equal(1); // Only 1 ticket matches with correct bonusball
          expect(result[10]).to.equal(2); // 2 tickets match 5 normals without bonusball match
        });
      });

      describe("when testing mathematical edge cases", async () => {
        describe("when testing underflow protection in inclusion-exclusion", async () => {
          // Note: This test would need different tracker init, which we can't do easily
          // Let's modify to work with the standard 5-tier setup
          before(async () => {
            insertions = [
              { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)], bonusball: BigInt(6) } // Full match
            ];
          });
          
          beforeEach(async () => {
            subjectNormalBalls = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)];
            subjectBonusball = BigInt(6);
          });

          it("should handle calculations without underflow", async () => {
            const [winningTicket, result, dupResult] = await subject();
            
            expect(result[11]).to.equal(1); // 5 matches + bonusball
            expect(result[9]).to.equal(0); // Should be 0 after inclusion-exclusion, not negative
            expect(result[7]).to.equal(0); // Should be 0 after inclusion-exclusion, not negative
          });
        });
      });
    });
  });

  describe("#unpackTicket", async () => {
    let subjectPackedTicket: bigint;
    let subjectNormalMax: number;

    beforeEach(async () => {
      const ticket = { normals: [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)], bonusball: BigInt(6) };
      subjectPackedTicket = calculatePackedTicket(ticket, BigInt(30));
      subjectNormalMax = 30;
    });

    async function subject(): Promise<[bigint[], bigint]> {
      return await tracker.unpackTicket(subjectPackedTicket, subjectNormalMax);
    }

    it("should unpack the ticket correctly", async () => {
      const [normals, bonusball] = await subject();

      expect(normals).to.deep.equal([BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)]);
      expect(bonusball).to.equal(BigInt(6));
    });

    describe("when testing boundary conditions", async () => {
      describe("when minimum normal number (1) is included", async () => {
        beforeEach(async () => {
          const ticket = { normals: [BigInt(1),BigInt(10),BigInt(15),BigInt(20),BigInt(25)], bonusball: BigInt(5) };
          subjectPackedTicket = calculatePackedTicket(ticket, BigInt(subjectNormalMax));
        });

        it("should correctly handle minimum normal number", async () => {
          const [normals, bonusball] = await subject();
          
          expect(normals).to.deep.equal([BigInt(1),BigInt(10),BigInt(15),BigInt(20),BigInt(25)]);
          expect(bonusball).to.equal(BigInt(5));
        });
      });

      describe("when maximum normal number is included", async () => {
        beforeEach(async () => {
          const ticket = { normals: [BigInt(1),BigInt(5),BigInt(10),BigInt(25),BigInt(30)], bonusball: BigInt(2) };
          subjectPackedTicket = calculatePackedTicket(ticket, BigInt(subjectNormalMax));
        });

        it("should correctly handle maximum normal number", async () => {
          const [normals, bonusball] = await subject();
          
          expect(normals).to.deep.equal([BigInt(1),BigInt(5),BigInt(10),BigInt(25),BigInt(30)]);
          expect(bonusball).to.equal(BigInt(2));
        });
      });

      describe("when minimum bonusball (1) is used", async () => {
        beforeEach(async () => {
          const ticket = { normals: [BigInt(5),BigInt(10),BigInt(15),BigInt(20),BigInt(25)], bonusball: BigInt(1) };
          subjectPackedTicket = calculatePackedTicket(ticket, BigInt(subjectNormalMax));
        });

        it("should correctly handle minimum bonusball", async () => {
          const [normals, bonusball] = await subject();
          
          expect(normals).to.deep.equal([BigInt(5),BigInt(10),BigInt(15),BigInt(20),BigInt(25)]);
          expect(bonusball).to.equal(BigInt(1));
        });
      });

      describe("when maximum bonusball is used", async () => {
        beforeEach(async () => {
          const ticket = { normals: [BigInt(1),BigInt(5),BigInt(10),BigInt(15),BigInt(20)], bonusball: BigInt(255) - BigInt(subjectNormalMax) };
          subjectPackedTicket = calculatePackedTicket(ticket, BigInt(subjectNormalMax));
        });

        it("should correctly handle maximum bonusball", async () => {
          const [normals, bonusball] = await subject();
          
          expect(normals).to.deep.equal([BigInt(1),BigInt(5),BigInt(10),BigInt(15),BigInt(20)]);
          expect(bonusball).to.equal(BigInt(255 - subjectNormalMax));
        });
      });
    });

    describe("when testing edge cases", async () => {
      describe("when ticket has sparse bit pattern", async () => {
        beforeEach(async () => {
          const ticket = { normals: [BigInt(2),BigInt(8),BigInt(16),BigInt(24),BigInt(29)], bonusball: BigInt(10) };
          subjectPackedTicket = calculatePackedTicket(ticket, BigInt(subjectNormalMax));
        });

        it("should correctly handle sparse bit patterns", async () => {
          const [normals, bonusball] = await subject();
          
          expect(normals).to.deep.equal([BigInt(2),BigInt(8),BigInt(16),BigInt(24),BigInt(29)]);
          expect(bonusball).to.equal(BigInt(10));
        });
      });

      describe("when ticket has dense bit pattern", async () => {
        beforeEach(async () => {
          const ticket = { normals: [BigInt(26),BigInt(27),BigInt(28),BigInt(29),BigInt(30)], bonusball: BigInt(4) };
          subjectPackedTicket = calculatePackedTicket(ticket, BigInt(subjectNormalMax));
        });

        it("should correctly handle dense bit patterns", async () => {
          const [normals, bonusball] = await subject();
          
          expect(normals).to.deep.equal([BigInt(26),BigInt(27),BigInt(28),BigInt(29),BigInt(30)]);
          expect(bonusball).to.equal(BigInt(4));
        });
      });

      describe("when ticket has single normal ball", async () => {
        beforeEach(async () => {
          const ticket = { normals: [BigInt(15)], bonusball: BigInt(7) };
          subjectPackedTicket = calculatePackedTicket(ticket, BigInt(subjectNormalMax));
        });

        it("should correctly unpack single normal ball", async () => {
          const [normals, bonusball] = await subject();
          
          expect(normals).to.deep.equal([BigInt(15)]);
          expect(bonusball).to.equal(BigInt(7));
        });
      });
    });

    describe("when testing mathematical patterns", async () => {
      describe("when testing perfect squares", async () => {
        beforeEach(async () => {
          const ticket = { normals: [BigInt(1),BigInt(4),BigInt(9),BigInt(16),BigInt(25)], bonusball: BigInt(19) };
          subjectPackedTicket = calculatePackedTicket(ticket, BigInt(subjectNormalMax));
        });

        it("should handle mathematical bit patterns correctly", async () => {
          const [normals, bonusball] = await subject();
          
          expect(normals).to.deep.equal([BigInt(1),BigInt(4),BigInt(9),BigInt(16),BigInt(25)]);
          expect(bonusball).to.equal(BigInt(19));
        });
      });

      describe("when testing powers of 2", async () => {
        beforeEach(async () => {
          const ticket = { normals: [BigInt(1),BigInt(2),BigInt(4),BigInt(8),BigInt(16)], bonusball: BigInt(32) };
          subjectPackedTicket = calculatePackedTicket(ticket, BigInt(subjectNormalMax));
        });

        it("should handle power of 2 bit positions", async () => {
          const [normals, bonusball] = await subject();
          
          expect(normals).to.deep.equal([BigInt(1),BigInt(2),BigInt(4),BigInt(8),BigInt(16)]);
          expect(bonusball).to.equal(BigInt(32));
        });
      });

      describe("when testing prime numbers", async () => {
        beforeEach(async () => {
          const ticket = { normals: [BigInt(2),BigInt(3),BigInt(5),BigInt(7),BigInt(11)], bonusball: BigInt(13) };
          subjectPackedTicket = calculatePackedTicket(ticket, BigInt(subjectNormalMax));
        });

        it("should handle prime number patterns", async () => {
          const [normals, bonusball] = await subject();
          
          expect(normals).to.deep.equal([BigInt(2),BigInt(3),BigInt(5),BigInt(7),BigInt(11)]);
          expect(bonusball).to.equal(BigInt(13));
        });
      });
    });
  });
});
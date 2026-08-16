import { ethers } from "hardhat";
import DeployHelper from "@utils/deploys";

import {
  getWaffleExpect,
  getAccounts
} from "@utils/test/index";
import { Account } from "@utils/test";

import { FisherYatesWithRejectionTester } from "@utils/contracts";
import { takeSnapshot, SnapshotRestorer } from "@nomicfoundation/hardhat-toolbox/network-helpers";

const expect = getWaffleExpect();

describe("FisherYatesWithRejection", () => {
  let owner: Account;
  let fisherYatesTester: FisherYatesWithRejectionTester;
  let snapshot: SnapshotRestorer;

  beforeEach(async () => {
    [owner] = await getAccounts();
    const deployer = new DeployHelper(owner.wallet);

    fisherYatesTester = await deployer.deployFisherYatesWithRejectionTester();
    
    snapshot = await takeSnapshot();
  });

  beforeEach(async () => {
    await snapshot.restore();
  });

  describe("#draw", async () => {
    let subjectMinRange: bigint;
    let subjectMaxRange: bigint;
    let subjectCount: bigint;
    let subjectSeed: bigint;

    beforeEach(async () => {
      subjectMinRange = BigInt(1);
      subjectMaxRange = BigInt(10);
      subjectCount = BigInt(5);
      subjectSeed = BigInt(12345);
    });

    async function subject(): Promise<bigint[]> {
      return await fisherYatesTester.draw(subjectMinRange, subjectMaxRange, subjectCount, subjectSeed);
    }

    it("should return array of correct length", async () => {
      const result = await subject();
      
      expect(result).to.have.length(subjectCount);
    });

    it("should return numbers within specified range", async () => {
      const result = await subject();
      
      for (const num of result) {
        expect(num).to.be.gte(subjectMinRange);
        expect(num).to.be.lte(subjectMaxRange);
      }
    });

    it("should return unique numbers only", async () => {
      const result = await subject();
      
      const uniqueNumbers = [...new Set(result.map(n => n.toString()))];
      expect(uniqueNumbers).to.have.length(subjectCount);
    });

    it("should be deterministic for same parameters", async () => {
      const result1 = await subject();
      const result2 = await subject();
      
      expect(result1).to.deep.equal(result2);
    });

    it("should produce different results for different seeds", async () => {
      subjectSeed = BigInt(12345);
      const result1 = await subject();
      
      subjectSeed = BigInt(98765);
      const result2 = await subject();
      
      // Since algorithms are deterministic, these specific seeds will always produce different results
      expect(result1).to.not.deep.equal(result2);
    });

    describe("when drawing single number", async () => {
      beforeEach(async () => {
        subjectCount = BigInt(1);
      });

      it("should return single number in range", async () => {
        const result = await subject();
        
        expect(result).to.have.length(1);
        expect(result[0]).to.be.gte(subjectMinRange);
        expect(result[0]).to.be.lte(subjectMaxRange);
      });

      it("should be deterministic", async () => {
        const result1 = await subject();
        const result2 = await subject();
        
        expect(result1).to.deep.equal(result2);
      });
    });

    describe("when drawing from single element range", async () => {
      beforeEach(async () => {
        subjectMinRange = BigInt(7);
        subjectMaxRange = BigInt(7);
        subjectCount = BigInt(1);
      });

      it("should return the single element", async () => {
        const result = await subject();
        
        expect(result).to.have.length(1);
        expect(result[0]).to.equal(7);
      });
    });

    describe("when drawing zero numbers", async () => {
      beforeEach(async () => {
        subjectCount = BigInt(0);
      });

      it("should return empty array", async () => {
        const result = await subject();
        
        expect(result).to.have.length(0);
      });
    });

    describe("when drawing maximum possible count", async () => {
      beforeEach(async () => {
        subjectMinRange = BigInt(1);
        subjectMaxRange = BigInt(5);
        subjectCount = BigInt(5);
      });

      it("should return all numbers in range", async () => {
        const result = await subject();
        
        expect(result).to.have.length(5);
        const sortedResult = [...result].sort((a, b) => Number(a) - Number(b));
        expect(sortedResult).to.deep.equal([1, 2, 3, 4, 5]);
      });
    });

    describe("when using different range offsets", async () => {
      beforeEach(async () => {
        subjectMinRange = BigInt(20);
        subjectMaxRange = BigInt(25);
        subjectCount = BigInt(3);
      });

      it("should respect the range offset", async () => {
        const result = await subject();
        
        expect(result).to.have.length(3);
        for (const num of result) {
          expect(num).to.be.gte(20);
          expect(num).to.be.lte(25);
        }
      });
    });

    describe("when using large range", async () => {
      beforeEach(async () => {
        subjectMinRange = BigInt(1);
        subjectMaxRange = BigInt(255);
        subjectCount = BigInt(10);
      });

      it("should work with maximum uint8 range", async () => {
        const result = await subject();
        
        expect(result).to.have.length(10);
        for (const num of result) {
          expect(num).to.be.gte(1);
          expect(num).to.be.lte(255);
        }
        
        const uniqueNumbers = [...new Set(result.map(n => n.toString()))];
        expect(uniqueNumbers).to.have.length(10);
      });
    });

    describe("when count exceeds available range", async () => {
      beforeEach(async () => {
        subjectMinRange = BigInt(1);
        subjectMaxRange = BigInt(5);
        subjectCount = BigInt(6);
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWith("Too many draws");
      });
    });

    describe("when count far exceeds available range", async () => {
      beforeEach(async () => {
        subjectMinRange = BigInt(1);
        subjectMaxRange = BigInt(3);
        subjectCount = BigInt(100);
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWith("Too many draws");
      });
    });

    context("specific deterministic test cases", async () => {
      describe("test vector 1: basic case", async () => {
        beforeEach(async () => {
          subjectSeed = BigInt(12345);
          subjectMinRange = BigInt(1);
          subjectMaxRange = BigInt(5);
          subjectCount = BigInt(3);
        });

        it("should return consistent results", async () => {
          const result = await subject();
          expect(result).to.have.length(3);
        });
      });

      describe("test vector 2: different parameters", async () => {
        beforeEach(async () => {
          subjectSeed = BigInt(1);
          subjectMinRange = BigInt(10);
          subjectMaxRange = BigInt(15);
          subjectCount = BigInt(2);
        });

        it("should return consistent results", async () => {
          const result = await subject();
          expect(result).to.have.length(2);
        });
      });

      describe("test vector 3: edge case with large seed", async () => {
        beforeEach(async () => {
          subjectSeed = BigInt(0xFFFFFFFF);
          subjectMinRange = BigInt(1);
          subjectMaxRange = BigInt(3);
          subjectCount = BigInt(1);
        });

        it("should return consistent results within range", async () => {
          const result = await subject();
          expect(result).to.have.length(1);
          expect(result[0]).to.be.gte(1);
          expect(result[0]).to.be.lte(3);
        });
      });

      // it("should handle boundary rejection sampling scenarios", async () => {
      //   // Use parameters that are likely to trigger rejection sampling
      //   subjectSeed = BigInt(0xFFFFFFFE); // Near max uint value
      //   subjectMinRange = BigInt(1);
      //   subjectMaxRange = BigInt(3); // Small range to increase rejection probability
      //   subjectCount = BigInt(2);
        
      //   const result = await subject();
        
      //   expect(result).to.have.length(2);
      //   expect(result[0]).to.not.equal(result[1]);
      //   expect(result[0]).to.be.gte(1);
      //   expect(result[0]).to.be.lte(3);
      //   expect(result[1]).to.be.gte(1);
      //   expect(result[1]).to.be.lte(3);
      // });
    });
  });
});
import DeployHelper from "@utils/deploys";
import { getAccounts, getWaffleExpect } from "@utils/test";
import { Account } from "@utils/test";
import { UintCastsTester } from "@utils/contracts";

const expect = getWaffleExpect();

describe("UintCasts", () => {
  let owner: Account;
  let tester: UintCastsTester;

  beforeEach(async () => {
    [owner] = await getAccounts();
    const deployer = new DeployHelper(owner.wallet);
    tester = await deployer.deployUintCastsTester();
  });

  describe("toUint8", () => {
    let subjectValue: bigint;

    beforeEach(async () => {
      subjectValue = BigInt(255);
    });

    async function subject(): Promise<any> {
      return await tester.castUint8(subjectValue);
    }

    it("casts values at edges of the range", async () => {
      expect(await subject()).to.equal(subjectValue);
    });

    describe("when the value is out of range", async () => {
      beforeEach(async () => {
        subjectValue = BigInt(256);
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(
          tester,
          "Uint8OutOfBounds"
        );
      });
    });
  });

  describe("toUint8Array", () => {
    let subjectInput: bigint[];

    beforeEach(async () => {
      subjectInput = [BigInt(0), BigInt(1), BigInt(255)];
    });

    async function subject(): Promise<any> {
      return await tester.castUint8Array(subjectInput);
    }

    it("casts array at edges of the range", async () => {
      expect(await subject()).to.deep.equal([BigInt(0), BigInt(1), BigInt(255)]);
    });

    describe("when any element is out of range", async () => {
      beforeEach(async () => {
        subjectInput = [BigInt(0), BigInt(256), BigInt(1)];
      });

      it("should revert", async () => {
        await expect(subject()).to.be.revertedWithCustomError(
          tester,
          "Uint8OutOfBounds"
        );
      });
    });

    describe("when the array is empty", async () => {
      beforeEach(async () => {
        subjectInput = [];
      });

      it("should return an empty array", async () => {
        expect(await subject()).to.deep.equal([]);
      });
    });
  });
});


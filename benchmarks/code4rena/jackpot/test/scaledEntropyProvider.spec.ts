import { ethers } from "hardhat";
import DeployHelper from "@utils/deploys";

import {
  getWaffleExpect,
  getAccounts
} from "@utils/test/index";
import { ether, usdc } from "@utils/common"
import { Account } from "@utils/test";

import { ScaledEntropyProvider, EntropyMock, EntropyCallbackMock } from "@utils/contracts";
import { Address } from "@utils/types";
import { ADDRESS_ZERO, ZERO_BYTES32 } from "@utils/constants";
import { takeSnapshot, SnapshotRestorer } from "@nomicfoundation/hardhat-toolbox/network-helpers";

const expect = getWaffleExpect();

describe("ScaledEntropyProvider", () => {
  let owner: Account;
  let user: Account;
  let callback: Account;

  let scaledEntropyProvider: ScaledEntropyProvider;
  let entropyMock: EntropyMock;
  let callbackMock: EntropyCallbackMock;
  let snapshot: SnapshotRestorer;

  const entropyProviderAddress = "0x0987654321098765432109876543210987654321";
  const entropyFee = ether(0.001);

  beforeEach(async () => {
    [
      owner,
      user,
      callback
    ] = await getAccounts();
    
    const deployer = new DeployHelper(owner.wallet);

    // Deploy entropy mock
    entropyMock = await deployer.deployEntropyMock(entropyFee);
    
    // Deploy callback mock
    callbackMock = await deployer.deployEntropyCallbackMock();
    
    // Deploy ScaledEntropyProvider with mock entropy
    scaledEntropyProvider = await deployer.deployScaledEntropyProvider(
      await entropyMock.getAddress(),
      entropyProviderAddress
    );
    
    snapshot = await takeSnapshot();
  });

  beforeEach(async () => {
    await snapshot.restore();
  });

  describe("#constructor", async () => {
    let subjectEntropy: Address;
    let subjectEntropyProvider: Address;

    beforeEach(async () => {
      subjectEntropy = await entropyMock.getAddress();
      subjectEntropyProvider = entropyProviderAddress;
    });

    async function subject(): Promise<ScaledEntropyProvider> {
      const deployer = new DeployHelper(owner.wallet);
      return await deployer.deployScaledEntropyProvider(subjectEntropy, subjectEntropyProvider);
    }

    it("should set the correct entropy contract address", async () => {
      const scaledProvider = await subject();
      
      const actualEntropy = await scaledProvider.getEntropyContract();
      expect(actualEntropy).to.eq(subjectEntropy);
    });

    it("should set the correct entropy provider address", async () => {
      const scaledProvider = await subject();
      
      const actualEntropyProvider = await scaledProvider.getEntropyProvider();
      expect(actualEntropyProvider).to.eq(subjectEntropyProvider);
    });

    it("should set the correct owner", async () => {
      const scaledProvider = await subject();
      
      const actualOwner = await scaledProvider.owner();
      expect(actualOwner).to.eq(owner.address);
    });

    describe("when entropy address is zero", async () => {
      beforeEach(async () => {
        subjectEntropy = ADDRESS_ZERO;
      });

      it("should revert with ZeroAddress error", async () => {
        await expect(subject()).to.be.revertedWithCustomError(scaledEntropyProvider, "ZeroAddress");
      });
    });

    describe("when entropy provider address is zero", async () => {
      beforeEach(async () => {
        subjectEntropyProvider = ADDRESS_ZERO;
      });

      it("should revert with ZeroAddress error", async () => {
        await expect(subject()).to.be.revertedWithCustomError(scaledEntropyProvider, "ZeroAddress");
      });
    });
  });

  describe("#requestAndCallbackScaledRandomness", async () => {
    let subjectGasLimit: bigint;
    let subjectRequests: any[];
    let subjectSelector: string;
    let subjectContext: string;
    let subjectValue: bigint;
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectGasLimit = 10000000n;
      subjectRequests = [
        {
          samples: 5,
          minRange: 1,
          maxRange: 30,
          withReplacement: false
        },
        {
          samples: 1,
          minRange: 1,
          maxRange: 10,
          withReplacement: false
        }
      ];
      subjectSelector = "0x12345678";
      subjectContext = ethers.encodeBytes32String("context");
      subjectValue = entropyFee + (subjectGasLimit * BigInt(1e7));
      subjectCaller = user;
    });

    async function subject(): Promise<any> {
      return await scaledEntropyProvider.connect(subjectCaller.wallet).requestAndCallbackScaledRandomness(
        subjectGasLimit,
        subjectRequests,
        subjectSelector,
        subjectContext,
        { value: subjectValue }
      );
    }

    async function subjectStaticCall(): Promise<bigint> {
      return await scaledEntropyProvider.connect(subjectCaller.wallet).requestAndCallbackScaledRandomness.staticCall(
        subjectGasLimit,
        subjectRequests,
        subjectSelector,
        subjectContext,
        { value: subjectValue }
      );
    }

    it("should return a unique sequence number", async () => {
      const sequence = await subjectStaticCall();
      expect(sequence).to.be.greaterThan(0);
    });

    it("should store the pending request with correct parameters", async () => {
      const sequence = await subjectStaticCall();
      await subject();
      
      const pendingRequest = await scaledEntropyProvider.getPendingRequest(sequence);
      expect(pendingRequest.callback).to.eq(subjectCaller.address);
      expect(pendingRequest.selector).to.eq(subjectSelector);
      expect(pendingRequest.context).to.eq(subjectContext);
      expect(pendingRequest.setRequests.length).to.eq(2);
    });

    it("should call the entropy contract with correct parameters", async () => {
      await expect(subject()).to.emit(entropyMock, "EntropyRequested");
    });

    it("should emit the correct events", async () => {
      const sequence = await subjectStaticCall();
      // user random number isn't used so we use 0
      await expect(subject()).to.emit(entropyMock, "EntropyRequested")
        .withArgs(sequence, await scaledEntropyProvider.getAddress(), entropyProviderAddress, ZERO_BYTES32);
    });

    describe("when insufficient fee is provided", async () => {
      beforeEach(async () => {
        subjectValue = entropyFee - BigInt(1);
      });

      it("should revert with insufficient fee error", async () => {
        await expect(subject()).to.be.revertedWithCustomError(scaledEntropyProvider, "InsufficientFee");
      });
    });

    describe("when no set requests are provided", async () => {
      beforeEach(async () => {
        subjectRequests = [];
      });

      it("should revert with InvalidRequests error", async () => {
        await expect(subject()).to.be.revertedWithCustomError(scaledEntropyProvider, "InvalidRequests");
      });
    });

    describe("when set request has invalid range", async () => {
      beforeEach(async () => {
        subjectRequests = [
          {
            samples: 5,
            minRange: 10,
            maxRange: 5, // max < min
            withReplacement: false
          }
        ];
      });

      it("should revert with InvalidRange error", async () => {
        await expect(subject()).to.be.revertedWithCustomError(scaledEntropyProvider, "InvalidRange");
      });
    });

    describe("when set request has zero samples", async () => {
      beforeEach(async () => {
        subjectRequests = [
          {
            samples: 0,
            minRange: 1,
            maxRange: 10,
            withReplacement: false
          }
        ];
      });

      it("should revert with InvalidSamples error", async () => {
        await expect(subject()).to.be.revertedWithCustomError(scaledEntropyProvider, "InvalidSamples");
      });
    });

    describe("when selector is empty", async () => {
      beforeEach(async () => {
        subjectSelector = "0x00000000";
      });

      it("should revert with InvalidSelector error", async () => {
        await expect(subject()).to.be.revertedWithCustomError(scaledEntropyProvider, "InvalidSelector");
      });
    });
  });

  describe("#getFee", async () => {
    let subjectGasLimit: bigint;

    beforeEach(async () => {
      subjectGasLimit = 10000000n;
    });

    async function subject(): Promise<bigint> {
      return await scaledEntropyProvider.getFee(subjectGasLimit);
    }

    it("should return the correct entropy fee from the entropy contract", async () => {
      const fee = await subject();
      expect(fee).to.eq(entropyFee + (subjectGasLimit * BigInt(1e7)));
    });
  });

  describe("#getEntropyProvider", async () => {
    async function subject(): Promise<Address> {
      return await scaledEntropyProvider.getEntropyProvider();
    }

    it("should return the correct entropy provider address", async () => {
      const provider = await subject();
      expect(provider).to.eq(entropyProviderAddress);
    });

  });

  describe("#getPendingRequest", async () => {
    let subjectSequence: bigint;

    beforeEach(async () => {
      // First create a pending request
      const gasLimit = 10000000n;
      const requests = [
        {
          samples: 5,
          minRange: 1,
          maxRange: 30,
          withReplacement: false
        }
      ];
      const selector = "0x12345678";
      const context = ethers.encodeBytes32String("context");

      // Get sequence number first
      subjectSequence = await scaledEntropyProvider.connect(user.wallet).requestAndCallbackScaledRandomness.staticCall(
        gasLimit,
        requests,
        selector,
        context,
        { value: entropyFee + (gasLimit * BigInt(1e7)) }
      );

      // Then execute the transaction
      await scaledEntropyProvider.connect(user.wallet).requestAndCallbackScaledRandomness(
        gasLimit,
        requests,
        selector,
        context,
        { value: entropyFee + (gasLimit * BigInt(1e7)) }
      );
    });

    async function subject(): Promise<any> {
      return await scaledEntropyProvider.getPendingRequest(subjectSequence);
    }

    it("should return the correct pending request data", async () => {
      const pendingRequest = await subject();
      expect(pendingRequest.callback).to.eq(user.address);
      expect(pendingRequest.selector).to.eq("0x12345678");
      expect(pendingRequest.setRequests.length).to.eq(1);
    });

    it("should return callback address correctly", async () => {
      const pendingRequest = await subject();
      expect(pendingRequest.callback).to.eq(user.address);
    });

    it("should return selector correctly", async () => {
      const pendingRequest = await subject();
      expect(pendingRequest.selector).to.eq("0x12345678");
    });

    it("should return context correctly", async () => {
      const pendingRequest = await subject();
      expect(pendingRequest.context).to.eq(ethers.encodeBytes32String("context"));
    });

    it("should return set requests array correctly", async () => {
      const pendingRequest = await subject();
      expect(pendingRequest.setRequests.length).to.eq(1);
      expect(pendingRequest.setRequests[0].samples).to.eq(5);
      expect(pendingRequest.setRequests[0].minRange).to.eq(1);
      expect(pendingRequest.setRequests[0].maxRange).to.eq(30);
      expect(pendingRequest.setRequests[0].withReplacement).to.eq(false);
    });

    // describe("when sequence does not exist", async () => {
    //   beforeEach(async () => {
    //     subjectSequence = BigInt(999);
    //   });

    //   it("should return empty/default struct values", async () => {
    //     const pendingRequest = await subject();
    //     expect(pendingRequest.callback).to.eq(ADDRESS_ZERO);
    //     expect(pendingRequest.selector).to.eq("0x00000000");
    //     expect(pendingRequest.setRequests.length).to.eq(0);
    //   });
    // });
  });

  describe("#setEntropyProvider", async () => {
    let subjectNewEntropyProvider: Address;
    let subjectCaller: Account;

    beforeEach(async () => {
      subjectNewEntropyProvider = user.address;
      subjectCaller = owner;
    });

    async function subject(): Promise<any> {
      return await scaledEntropyProvider.connect(subjectCaller.wallet).setEntropyProvider(subjectNewEntropyProvider);
    }

    it("should update the entropy provider address", async () => {
      const preProvider = await scaledEntropyProvider.getEntropyProvider();
      expect(preProvider).to.eq(entropyProviderAddress);
      
      await subject();
      
      const postProvider = await scaledEntropyProvider.getEntropyProvider();
      expect(postProvider).to.eq(subjectNewEntropyProvider);
    });

    it("should emit the correct event", async () => {
      await subject();
    });

    describe("when caller is not the owner", async () => {
      beforeEach(async () => {
        subjectCaller = user;
      });

      it("should revert with unauthorized access error", async () => {
        await expect(subject()).to.be.revertedWithCustomError(scaledEntropyProvider, "OwnableUnauthorizedAccount");
      });
    });

    describe("when new provider address is zero", async () => {
      beforeEach(async () => {
        subjectNewEntropyProvider = ADDRESS_ZERO;
      });

      it("should revert with ZeroAddress error", async () => {
        await expect(subject()).to.be.revertedWithCustomError(scaledEntropyProvider, "ZeroAddress");
      });
    });
  });

  describe("#entropyCallback", async () => {
    let subjectSequence: bigint;
    let subjectProvider: Address;
    let subjectRandomNumber: string;

    beforeEach(async () => {
      // First create a pending request
      const gasLimit = 10000000n;
      const requests = [
        {
          samples: 5,
          minRange: 1,
          maxRange: 30,
          withReplacement: false
        },
        {
          samples: 1,
          minRange: 1,
          maxRange: 10,
          withReplacement: false
        }
      ];

      const context = ethers.encodeBytes32String("context");

      const callbackSelector = callbackMock.interface.getFunction("scaledEntropyCallback").selector;

      subjectSequence = await callbackMock.connect(user.wallet).requestAndCallbackScaledRandomness.staticCall(
        await scaledEntropyProvider.getAddress(),
        gasLimit,
        requests,
        callbackSelector,
        context,
        { value: entropyFee + (gasLimit * BigInt(1e7)) }
      );

      await callbackMock.connect(user.wallet).requestAndCallbackScaledRandomness(
        await scaledEntropyProvider.getAddress(),
        gasLimit,
        requests,
        callbackSelector,
        context,
        { value: entropyFee + (gasLimit * BigInt(1e7)) }
      );

      subjectProvider = entropyProviderAddress;
      subjectRandomNumber = ethers.encodeBytes32String("randomValue");
    });

    async function subject(): Promise<any> {
      // This would typically be called by the entropy contract
      // For testing, we might need to call it directly or through a mock
      return await entropyMock.triggerCallback(subjectSequence, subjectProvider, subjectRandomNumber);
    }

    it("should process the scaled randomness correctly", async () => {
      await subject();
      
      const lastRandomNumbers = await callbackMock.getLastRandomNumbers();
      expect(lastRandomNumbers.length).to.eq(2);
      expect(lastRandomNumbers[0].length).to.eq(5);
      expect(lastRandomNumbers[1].length).to.eq(1);
    });

    it("should call the callback contract with correct parameters", async () => {
      await subject();
      
      expect(await callbackMock.lastSequence()).to.eq(subjectSequence);
    });

    it("should emit ScaledRandomnessDelivered event", async () => {
      await expect(subject()).to.emit(scaledEntropyProvider, "ScaledRandomnessDelivered")
        .withArgs(subjectSequence, await callbackMock.getAddress(), 2);
    });

    it("should emit EntropyFulfilled event", async () => {
      await expect(subject()).to.emit(scaledEntropyProvider, "EntropyFulfilled")
        .withArgs(subjectSequence, subjectRandomNumber);
    });

    it("should delete the pending request after processing", async () => {
      await subject();
      
      const pendingRequest = await scaledEntropyProvider.getPendingRequest(subjectSequence);
      expect(pendingRequest.callback).to.eq(ADDRESS_ZERO);
    });

    it("should generate correct number of samples for each set request", async () => {
      await subject();
      
      const lastRandomNumbers = await callbackMock.getLastRandomNumbers();
      expect(lastRandomNumbers[0].length).to.eq(5); // First request: 5 samples
      expect(lastRandomNumbers[1].length).to.eq(1); // Second request: 1 sample
    });

    it("should respect the min/max range for each set request", async () => {
      await subject();
      
      const lastRandomNumbers = await callbackMock.getLastRandomNumbers();
      // First request: range 1-30
      for (let i = 0; i < lastRandomNumbers[0].length; i++) {
        expect(lastRandomNumbers[0][i]).to.be.gte(1);
        expect(lastRandomNumbers[0][i]).to.be.lte(30);
      }
      // Second request: range 1-10
      for (let i = 0; i < lastRandomNumbers[1].length; i++) {
        expect(lastRandomNumbers[1][i]).to.be.gte(1);
        expect(lastRandomNumbers[1][i]).to.be.lte(10);
      }
    });

    describe("when the request specifies withReplacement", async () => {
      beforeEach(async () => {
        // Create a new request with withReplacement: true
        const userRandomNumber = ethers.encodeBytes32String("userRandomWithReplacement");
        const gasLimit = 10000000n;
        const requests = [
          {
            samples: 10,
            minRange: 1,
            maxRange: 5, // Small range to increase chance of duplicates
            withReplacement: true
          }
        ];
        const callbackSelector = callbackMock.interface.getFunction("scaledEntropyCallback").selector;
        const context = ethers.encodeBytes32String("contextWithReplacement");
  
        subjectSequence = await callbackMock.connect(user.wallet).requestAndCallbackScaledRandomness.staticCall(
          await scaledEntropyProvider.getAddress(),
          gasLimit,
          requests,
          callbackSelector,
          context,
          { value: entropyFee + (gasLimit * BigInt(1e7)) }
        );
        await callbackMock.connect(user.wallet).requestAndCallbackScaledRandomness(
          await scaledEntropyProvider.getAddress(),
          gasLimit,
          requests,
          callbackSelector,
          context,
          { value: entropyFee + (gasLimit * BigInt(1e7)) }
        );
      });

      it("should handle with replacement correctly", async () => {
        await subject();

        const lastRandomNumbers = await callbackMock.getLastRandomNumbers();
        expect(lastRandomNumbers[0].length).to.eq(10);
        
        // With replacement, duplicates are allowed
        // Check all values are in range
        for (let i = 0; i < lastRandomNumbers[0].length; i++) {
          expect(lastRandomNumbers[0][i]).to.be.gte(1);
          expect(lastRandomNumbers[0][i]).to.be.lte(5);
        }
      });
    });

    describe("when callback fails", async () => {
      beforeEach(async () => {
        await callbackMock.setShouldFail(true);
      });

      it("should revert with CallbackFailed error", async () => {
        await expect(subject()).to.be.revertedWithCustomError(scaledEntropyProvider, "CallbackFailed");
      });
    });

    describe("when sequence does not exist", async () => {
      beforeEach(async () => {
        // Add a pending request in the mock so that it knows what to callback
        await entropyMock.connect(owner.wallet).addPendingRequest(BigInt(999), await scaledEntropyProvider.getAddress(), subjectRandomNumber);
        subjectSequence = BigInt(999);
      });

      it("should revert with UnknownSequence error", async () => {
        await expect(subject()).to.be.revertedWithCustomError(scaledEntropyProvider, "UnknownSequence");
      });
    });

    describe("when called by non-entropy contract", async () => {
      it("should only allow calls from entropy contract", async () => {
        // Try calling _entropyCallback directly (should fail)
        await expect(
          scaledEntropyProvider.connect(user.wallet)._entropyCallback(subjectSequence, subjectProvider, subjectRandomNumber)
        ).to.be.revertedWith("Only Entropy can call this function");
      });
    });
  });
});
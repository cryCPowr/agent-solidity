import { Signer } from "ethers";

import {
  EntropyCallbackMock,
  EntropyMock,
  ETHRejectingContract,
  FisherYatesWithRejectionTester,
  GuaranteedMinimumPayoutCalculator,
  Jackpot,
  JackpotBridgeManager,
  JackpotLPManager,
  JackpotTicketNFT,
  MockDepository,
  MockJackpot,
  ReentrantUSDCMock,
  ScaledEntropyProvider,
  ScaledEntropyProviderMock,
  TicketComboTrackerTester,
  UintCastsTester,
  USDCMock,
} from "./contracts";

import {
  GuaranteedMinimumPayoutCalculator__factory,
  Jackpot__factory,
  JackpotBridgeManager__factory,
  JackpotLPManager__factory,
  JackpotTicketNFT__factory,
  ScaledEntropyProvider__factory,
} from "../typechain-types/factories/contracts";
import {FisherYatesRejection__factory } from "../typechain-types/factories/contracts/lib/FisherYatesWithRejection.sol";

import {
  EntropyCallbackMock__factory,
  EntropyMock__factory,
  ETHRejectingContract__factory,
  FisherYatesWithRejectionTester__factory,
  MockDepository__factory,
  MockJackpot__factory,
  ReentrantUSDCMock__factory,
  ScaledEntropyProviderMock__factory,
  TicketComboTrackerTester__factory,
  UintCastsTester__factory,
  USDCMock__factory,
} from "../typechain-types/factories/contracts/mocks";
import { Address } from "./types";

export default class DeployHelper {
    private _deployerSigner: Signer;
  
    constructor(deployerSigner: Signer) {
      this._deployerSigner = deployerSigner;
    }
  
    public async deployUSDCMock(mintAmount: bigint, name: string, symbol: string): Promise<USDCMock> {
      return await new USDCMock__factory(this._deployerSigner).deploy(mintAmount, name, symbol);
    }

    public async deployReentrantUSDCMock(mintAmount: bigint, name: string, symbol: string): Promise<ReentrantUSDCMock> {
      return await new ReentrantUSDCMock__factory(this._deployerSigner).deploy(mintAmount, name, symbol);
    }

    public async deployScaledEntropyProviderMock(
      fee: bigint,
      callback: string,
      selector: string
    ): Promise<ScaledEntropyProviderMock> {
      return await new ScaledEntropyProviderMock__factory(this._deployerSigner).deploy(fee, callback, selector);
    }

    public async deployJackpot(
        drawingDurationInSeconds: bigint,
        normalBallMax: bigint,
        bonusballMin: bigint,
        lpEdgeTarget: bigint,
        reserveRatio: bigint,
        referralFeeBps: bigint,
        referralWinShareBps: bigint,
        protocolFeeBps: bigint,
        protocolFeeThreshold: bigint,
        ticketPrice: bigint,
        maxReferrers: bigint,
        entropyBaseGasLimit: bigint
    ): Promise<Jackpot> {
      return await new Jackpot__factory(this._deployerSigner).deploy(
        drawingDurationInSeconds,
        normalBallMax,
        bonusballMin,
        lpEdgeTarget,
        reserveRatio,
        referralFeeBps,
        referralWinShareBps,
        protocolFeeBps,
        protocolFeeThreshold,
        ticketPrice,
        maxReferrers,
        entropyBaseGasLimit
      );
    }

    public async deployJackpotLPManager(jackpot: Address): Promise<JackpotLPManager> {
      return await new JackpotLPManager__factory(this._deployerSigner).deploy(jackpot);
    }

    public async deployJackpotTicketNFT(jackpot: Address): Promise<JackpotTicketNFT> {
      return await new JackpotTicketNFT__factory(this._deployerSigner).deploy(jackpot);
    }

    public async deployJackpotBridgeManager(
      jackpot: Address,
      jackpotTicketNFT: Address,
      usdc: Address,
      name: string,
      version: string
    ): Promise<JackpotBridgeManager> {
      return await new JackpotBridgeManager__factory(this._deployerSigner).deploy(jackpot, jackpotTicketNFT, usdc, name, version);
    }

    public async deployGuaranteedMinimumPayoutCalculator(
      jackpot: Address,
      minimumPayout: bigint,
      premiumTierMinAllocation: bigint,
      minPayoutTiers: boolean[],
      premiumTierWeights: bigint[]
    ): Promise<GuaranteedMinimumPayoutCalculator> {
      return await new GuaranteedMinimumPayoutCalculator__factory(this._deployerSigner).deploy(
        jackpot,
        minimumPayout,
        premiumTierMinAllocation,
        minPayoutTiers,
        premiumTierWeights
      );
    }

    public async deployMockDepository(usdc: Address): Promise<MockDepository> {
      return await new MockDepository__factory(this._deployerSigner).deploy(usdc);
    }

    public async deployFisherYatesWithRejectionTester(): Promise<FisherYatesWithRejectionTester> {
      // Deploy the library first
      const fisherYatesLibrary = await new FisherYatesRejection__factory(this._deployerSigner).deploy();
      
      return await new FisherYatesWithRejectionTester__factory(
        {
          "contracts/lib/FisherYatesWithRejection.sol:FisherYatesRejection": await fisherYatesLibrary.getAddress()
        },
        this._deployerSigner
      ).deploy();
    }

    public async deployEntropyMock(fee: bigint): Promise<EntropyMock> {
      return await new EntropyMock__factory(this._deployerSigner).deploy(fee);
    }

    public async deployEntropyCallbackMock(): Promise<EntropyCallbackMock> {
      return await new EntropyCallbackMock__factory(this._deployerSigner).deploy();
    }

    public async deployTicketComboTrackerTester(): Promise<TicketComboTrackerTester> {
      return await new TicketComboTrackerTester__factory(this._deployerSigner).deploy();
    }

    public async deployUintCastsTester(): Promise<UintCastsTester> {
      return await new UintCastsTester__factory(this._deployerSigner).deploy();
    }

    public async deployScaledEntropyProvider(
      entropyAddress: string,
      entropyProviderAddress: string
    ): Promise<ScaledEntropyProvider> {
      // Deploy the library first
      const fisherYatesLibrary = await new FisherYatesRejection__factory(this._deployerSigner).deploy();
      
      return await new ScaledEntropyProvider__factory(
        {
          "contracts/lib/FisherYatesWithRejection.sol:FisherYatesRejection": await fisherYatesLibrary.getAddress()
        },
        this._deployerSigner
      ).deploy(entropyAddress, entropyProviderAddress);
    }

    public async deployMockJackpot(): Promise<MockJackpot> {
      return await new MockJackpot__factory(this._deployerSigner).deploy();
    }

    public async deployETHRejectingContract(): Promise<ETHRejectingContract> {
      return await new ETHRejectingContract__factory(this._deployerSigner).deploy();
    }
}

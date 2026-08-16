import DeployHelper from "@utils/deploys";
import { getAccounts } from "@utils/test/accountUtils";
import { ether, usdc } from "@utils/common";
import { ONE_DAY_IN_SECONDS } from "@utils/constants";
import { JackpotSystemFixture } from "@utils/types";

import {
  GuaranteedMinimumPayoutCalculator,
  Jackpot,
  JackpotLPManager,
  JackpotTicketNFT,
  ReentrantUSDCMock,
  ScaledEntropyProviderMock,
} from "@utils/contracts";

export async function deployJackpotSystem(): Promise<JackpotSystemFixture> {
  // Get accounts
  const [
    owner,
    user,
    lpOne,
    buyerOne,
    buyerTwo,
    referrerOne,
    referrerTwo,
    referrerThree,
  ] = await getAccounts();

  // Deployment parameters
  const deploymentParams = {
    drawingDurationInSeconds: ONE_DAY_IN_SECONDS,
    normalBallMax: BigInt(30),
    bonusballMin: BigInt(5),
    lpEdgeTarget: ether(0.3),
    reserveRatio: ether(0.2),
    referralFee: ether(0.065),
    referralWinShare: ether(0.05),
    protocolFee: ether(0.01),
    protocolFeeThreshold: usdc(1),
    ticketPrice: usdc(1),
    maxReferrers: BigInt(5),
    entropyBaseGasLimit: BigInt(10000000),
    entropyVariableGasLimit: BigInt(500000),
    entropyFee: ether(0.00005),
    minimumPayout: usdc(1),
    premiumTierMinAllocation: ether(.2),
    premiumTierWeights: [
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
    ],
    minPayoutTiers: [
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
      true,
    ] as boolean[],
  };

  const deployer = new DeployHelper(owner.wallet);

  // Deploy USDC Mock with large initial supply
  const usdcMock: ReentrantUSDCMock = await deployer.deployReentrantUSDCMock(usdc(1000000000), "USDC", "USDC");
  
  // Transfer USDC to test accounts
  await usdcMock.connect(owner.wallet).transfer(lpOne.address, usdc(100000000));
  await usdcMock.connect(owner.wallet).transfer(buyerOne.address, usdc(1000));
  await usdcMock.connect(owner.wallet).transfer(buyerTwo.address, usdc(1000));

  // Deploy core Jackpot contract
  const jackpot: Jackpot = await deployer.deployJackpot(
    deploymentParams.drawingDurationInSeconds,
    deploymentParams.normalBallMax,
    deploymentParams.bonusballMin,
    deploymentParams.lpEdgeTarget,
    deploymentParams.reserveRatio,
    deploymentParams.referralFee,
    deploymentParams.referralWinShare,
    deploymentParams.protocolFee,
    deploymentParams.protocolFeeThreshold,
    deploymentParams.ticketPrice,
    deploymentParams.maxReferrers,
    deploymentParams.entropyBaseGasLimit
  );

  // Deploy supporting contracts
  const jackpotNFT: JackpotTicketNFT = await deployer.deployJackpotTicketNFT(await jackpot.getAddress());
  const jackpotLPManager: JackpotLPManager = await deployer.deployJackpotLPManager(await jackpot.getAddress());
  
  const payoutCalculator: GuaranteedMinimumPayoutCalculator = await deployer.deployGuaranteedMinimumPayoutCalculator(
    await jackpot.getAddress(),
    deploymentParams.minimumPayout,
    deploymentParams.premiumTierMinAllocation,
    deploymentParams.minPayoutTiers,
    deploymentParams.premiumTierWeights
  );

  const entropyProvider: ScaledEntropyProviderMock = await deployer.deployScaledEntropyProviderMock(
    deploymentParams.entropyFee,
    await jackpot.getAddress(),
    jackpot.interface.getFunction("scaledEntropyCallback").selector
  );

  return {
    // Accounts
    owner,
    user,
    lpOne,
    buyerOne,
    buyerTwo,
    referrerOne,
    referrerTwo,
    referrerThree,

    // Contracts
    jackpot,
    jackpotLPManager,
    jackpotNFT,
    payoutCalculator,
    usdcMock,
    entropyProvider,

    // Parameters
    deploymentParams,

    // Helper
    deployer,
  };
}
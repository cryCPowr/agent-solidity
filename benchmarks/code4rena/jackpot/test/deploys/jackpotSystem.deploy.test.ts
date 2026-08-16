import { expect } from "chai";
import { ethers } from "hardhat";
import hre from "hardhat";
import JackpotSystemModule from "../../ignition/modules/JackpotSystem";
import fs from "fs";
import path from "path";

// Only run when explicitly requested
const runDeployTests = process.env.RUN_DEPLOY_TESTS === "true";
const ddescribe = runDeployTests ? describe : describe.skip;

ddescribe("Ignition Deploy: JackpotSystem", function () {
  this.timeout(180_000);

  // Shared across tests, re-initialized before each
  let P: any;
  let jackpot: any, jackpotNFT: any, jackpotLPManager: any, payoutCalculator: any, bridgeManager: any, entropyProvider: any, usdc: any;
  let multisigForAssert: string;

  beforeEach(async () => {
    const networkName = hre.network.name;
    const paramsFile = networkName === "localhost" ? "localhost.json"
      : networkName === "sepolia" ? "testnet.json"
      : networkName === "mainnet" ? "production.json"
      : "localhost.json"; // default for hardhat

    const paramsPath = path.join(__dirname, `../../ignition/parameters/${paramsFile}`);
    const raw = fs.readFileSync(paramsPath, "utf8");
    const loadedParams = JSON.parse(raw) as any;

    if (networkName === "hardhat") {
      multisigForAssert = (await ethers.getSigners())[1].address;
      loadedParams.JackpotSystem.multiSigAddress = multisigForAssert;

      const deployment = await (hre as any).ignition.deploy(JackpotSystemModule, {
        parameters: loadedParams,
      });

      ({ jackpot, jackpotNFT, jackpotLPManager, payoutCalculator, bridgeManager, entropyProvider, usdc } = deployment);
    } else {
      const { chainId } = await ethers.provider.getNetwork();
      const depPath = path.join(__dirname, `../../ignition/deployments/chain-${chainId}/deployed_addresses.json`);
      if (!fs.existsSync(depPath)) {
        throw new Error(`Missing ignition deployed addresses at ${depPath}`);
      }
      const dep = JSON.parse(fs.readFileSync(depPath, "utf8"));
      const addr = (name: string) => dep[`JackpotSystem#${name}`];

      jackpot = await ethers.getContractAt("Jackpot", addr("Jackpot"));
      jackpotNFT = await ethers.getContractAt("JackpotTicketNFT", addr("JackpotTicketNFT"));
      jackpotLPManager = await ethers.getContractAt("JackpotLPManager", addr("JackpotLPManager"));
      payoutCalculator = await ethers.getContractAt("GuaranteedMinimumPayoutCalculator", addr("GuaranteedMinimumPayoutCalculator"));
      bridgeManager = await ethers.getContractAt("JackpotBridgeManager", addr("JackpotBridgeManager"));
      entropyProvider = await ethers.getContractAt("ScaledEntropyProvider", addr("ScaledEntropyProvider"));
      usdc = await ethers.getContractAt("USDCMock", addr("USDCMock"));

      multisigForAssert = loadedParams.JackpotSystem.multiSigAddress;
    }

    P = loadedParams.JackpotSystem;
  });

  it("deploys/attaches contracts and verifies Jackpot constructor params", async () => {
    for (const c of [jackpot, jackpotNFT, jackpotLPManager, payoutCalculator, bridgeManager, entropyProvider, usdc]) {
      expect(await c.getAddress()).to.properAddress;
    }

    expect((await jackpot.drawingDurationInSeconds()).toString()).to.eq(P.drawingDurationInSeconds);
    expect((await jackpot.normalBallMax()).toString()).to.eq(P.normalBallMax);
    expect((await jackpot.bonusballMin()).toString()).to.eq(P.bonusballMin);
    expect((await jackpot.lpEdgeTarget()).toString()).to.eq(P.lpEdgeTarget);
    expect((await jackpot.reserveRatio()).toString()).to.eq(P.reserveRatio);
    expect((await jackpot.referralFee()).toString()).to.eq(P.referralFee);
    expect((await jackpot.referralWinShare()).toString()).to.eq(P.referralWinShare);
    expect((await jackpot.protocolFee()).toString()).to.eq(P.protocolFee);
    expect((await jackpot.protocolFeeThreshold()).toString()).to.eq(P.protocolFeeThreshold);
    expect((await jackpot.ticketPrice()).toString()).to.eq(P.ticketPrice);
    expect((await jackpot.maxReferrers()).toString()).to.eq(P.maxReferrers);
    expect((await jackpot.entropyBaseGasLimit()).toString()).to.eq(P.entropyBaseGasLimit);
  });

  it("verifies Jackpot initialization wiring and protocol fee recipient", async () => {
    expect(await jackpot.usdc()).to.eq(await usdc.getAddress());
    expect(await jackpot.jackpotLPManager()).to.eq(await jackpotLPManager.getAddress());
    expect(await jackpot.jackpotNFT()).to.eq(await jackpotNFT.getAddress());
    expect(await jackpot.entropy()).to.eq(await entropyProvider.getAddress());
    expect(await jackpot.payoutCalculator()).to.eq(await payoutCalculator.getAddress());
    expect(await jackpot.protocolFeeAddress()).to.eq(multisigForAssert);
  });

  it("verifies ownership transfers to multisig", async () => {
    expect(await jackpot.owner()).to.eq(multisigForAssert);
    expect(await payoutCalculator.owner()).to.eq(multisigForAssert);
    expect(await bridgeManager.owner()).to.eq(multisigForAssert);
    expect(await entropyProvider.owner()).to.eq(multisigForAssert);
  });

  it("verifies supporting contracts wiring and parameters", async () => {
    // NFT & LP manager wiring
    expect(await jackpotNFT.jackpot()).to.eq(await jackpot.getAddress());
    expect(await jackpotLPManager.jackpot()).to.eq(await jackpot.getAddress());

    // Payout calculator params
    expect(await payoutCalculator.jackpot()).to.eq(await jackpot.getAddress());
    expect((await payoutCalculator.minimumPayout()).toString()).to.eq(P.minimumPayout);
    const tiers = await payoutCalculator.getMinPayoutTiers();
    expect(tiers.map((b: boolean) => b)).to.deep.eq(P.minPayoutTiers);
    const weights = await payoutCalculator.getPremiumTierWeights();
    expect(weights.map((w: any) => w.toString())).to.deep.eq(P.premiumTierWeights);

    // Entropy provider params
    expect(await entropyProvider.getEntropyContract()).to.eq(P.entropyAddress);
    expect(await entropyProvider.getEntropyProvider()).to.eq(P.entropyProviderAddress);

    // Bridge manager wiring
    expect(await bridgeManager.jackpot()).to.eq(await jackpot.getAddress());
    expect(await bridgeManager.jackpotTicketNFT()).to.eq(await jackpotNFT.getAddress());
    expect(await bridgeManager.usdc()).to.eq(await usdc.getAddress());

    // USDC supply
    expect((await usdc.totalSupply()).toString()).to.eq(P.usdcInitialSupply);
  });
});

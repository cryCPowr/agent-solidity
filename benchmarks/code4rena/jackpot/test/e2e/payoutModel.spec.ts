import { ethers } from "hardhat";

import {
  getWaffleExpect,
  getAccounts
} from "@utils/test/index";
import { ether, usdc } from "@utils/common"
import { Account } from "@utils/test";

import { PRECISE_UNIT } from "@utils/constants";

import {
  GuaranteedMinimumPayoutCalculator,
  Jackpot,
  JackpotLPManager,
  JackpotTicketNFT,
  ReentrantUSDCMock,
  ScaledEntropyProviderMock,
} from "@utils/contracts";
import { JackpotSystemFixture, Ticket } from "@utils/types";
import { deployJackpotSystem } from "@utils/test/jackpotFixture";
import { calculateTierTotalWinners } from "@utils/protocolUtils";
import { time } from "@nomicfoundation/hardhat-toolbox/network-helpers";

const expect = getWaffleExpect();

// TODO: Check specific values against base case to make sure we have tests that validate the
// specific math not just an invariant holds
// TODO: Add tests for duplicates

type Scenario = {
  reserveRatio: bigint;       // 1e18-scaled
  lpEdgeTarget: bigint;       // 1e18-scaled
  minimumPayout: bigint;      // USDC (6 decimals)
  premiumTierWeights: bigint[]; // length 12, sum to PRECISE_UNIT, weights[0]=weights[1]=0
  weightsLabel: string;
};

function cartesian<T>(...lists: T[][]): T[][] {
  return lists.reduce<T[][]>((acc, list) => acc.flatMap(a => list.map(b => [...a, b] as T[])), [[]]);
}

function scenarioName(s: Scenario): string {
  const pct = (x: bigint) => `${Number(x) / 1e16}%`;
  return `rr=${pct(s.reserveRatio)} edge=${pct(s.lpEdgeTarget)} min=$${Number(s.minimumPayout) / 1e6} w=${s.weightsLabel}`;
}

describe.only("Payout Model", () => {
  let owner: Account;
  let buyerOne: Account;
  let buyerTwo: Account;
  let referrerOne: Account;
  let referrerTwo: Account;
  let referrerThree: Account;
  let solver: Account;

  let jackpotSystem: JackpotSystemFixture;
  let jackpot: Jackpot;
  let jackpotNFT: JackpotTicketNFT;
  let jackpotLPManager: JackpotLPManager;
  let payoutCalculator: GuaranteedMinimumPayoutCalculator;
  let usdcMock: ReentrantUSDCMock;
  let entropyProvider: ScaledEntropyProviderMock;

  async function runScenario(s: Scenario) {
    [owner, buyerOne, buyerTwo, referrerOne, referrerTwo, referrerThree, solver] = await getAccounts();

    jackpotSystem = await deployJackpotSystem();
    ({ jackpot, jackpotNFT, jackpotLPManager, payoutCalculator, usdcMock, entropyProvider } = jackpotSystem);

    await jackpot.connect(owner.wallet).initialize(
      usdcMock.getAddress(),
      await jackpotLPManager.getAddress(),
      await jackpotNFT.getAddress(),
      entropyProvider.getAddress(),
      await payoutCalculator.getAddress()
    );

    await usdcMock.connect(owner.wallet).transfer(buyerOne.address, usdc(1000));

    await jackpot.connect(owner.wallet).initializeLPDeposits(usdc(10000000));

    await usdcMock.connect(owner.wallet).approve(jackpot.getAddress(), usdc(3000000));
    await jackpot.connect(owner.wallet).lpDeposit(usdc(3000000));

    // Parameterize drawing
    await jackpot.connect(owner.wallet).setNormalBallMax(BigInt(35));
    await jackpot.connect(owner.wallet).setReserveRatio(s.reserveRatio);
    await jackpot.connect(owner.wallet).setLpEdgeTarget(s.lpEdgeTarget);
    await jackpot.connect(owner.wallet).setBonusballMin(BigInt(9));
    await payoutCalculator.connect(owner.wallet).setMinimumPayout(s.minimumPayout);
    // Ensure no payouts to tier 0 or 1 via minimums as well
    await payoutCalculator.connect(owner.wallet).setMinPayoutTiers([
      false, false,  true,  true,  true,  true,
       true,  true,  true,  true,  true,  true
    ]);
    await payoutCalculator.connect(owner.wallet).setPremiumTierWeights(s.premiumTierWeights);

    await jackpot.connect(owner.wallet).initializeJackpot(BigInt(await time.latest()) + BigInt(jackpotSystem.deploymentParams.drawingDurationInSeconds));

    await usdcMock.connect(buyerOne.wallet).approve(jackpot.getAddress(), usdc(1));
    await jackpot.connect(buyerOne.wallet).buyTickets([
      { normals: [1n, 2n, 3n, 4n, 5n], bonusball: 1n } as unknown as Ticket,
    ], buyerOne.address, [], [], ethers.encodeBytes32String("test"));

    await time.increase(jackpotSystem.deploymentParams.drawingDurationInSeconds);
    const drawingState = await jackpot.getDrawingState(1);
    const value = jackpotSystem.deploymentParams.entropyFee + ((jackpotSystem.deploymentParams.entropyBaseGasLimit + jackpotSystem.deploymentParams.entropyVariableGasLimit * drawingState.bonusballMax) * 10_000_000n);
    await jackpot.runJackpot({ value });

    const winningNumbers = [[1n, 2n, 3n, 4n, 5n], [6n]];
    await entropyProvider.randomnessCallback(winningNumbers);

    // Invariants
    const payouts = await payoutCalculator.getDrawingTierPayouts(1n);
    const ds = await jackpot.getDrawingState(1);
    let totalPayout = 0n;
    for (let i = 0; i < 12; i++) {
      totalPayout += payouts[i] * calculateTierTotalWinners(i, ds.ballMax, ds.bonusballMax, 0n);
    }

    expect(totalPayout).to.be.lte(ds.prizePool);
  }

  // Helpers to build premium weights excluding tiers 0 and 1 and normalize to PRECISE_UNIT
  function normalizeWeights(raw: bigint[]): bigint[] {
    if (raw.length !== 12) throw new Error("weights length must be 12");
    const w = [...raw];
    w[0] = 0n; w[1] = 0n; // enforce no payout to tier 0 or 1
    const sum = w.reduce((acc, v) => acc + v, 0n);
    if (sum === 0n) throw new Error("weights sum cannot be zero");
    const scaled = w.map(v => (v * PRECISE_UNIT) / sum);
    const scaledSum = scaled.reduce((acc, v) => acc + v, 0n);
    // Fix rounding remainder by adding to the highest tier (11) to keep sum exact
    if (scaledSum !== PRECISE_UNIT) {
      scaled[11] += (PRECISE_UNIT - scaledSum);
    }
    return scaled;
  }

  function randomWeightsUnseeded(label: string): { label: string; weights: bigint[] } {
    const raw: bigint[] = new Array(12).fill(0n);
    for (let i = 2; i < 12; i++) {
      const v = 1 + Math.floor(Math.random() * 1000); // 1..1000
      raw[i] = BigInt(v);
    }
    return { label, weights: normalizeWeights(raw) };
  }

  const randomVariants: { label: string; weights: bigint[] }[] = [
    randomWeightsUnseeded("rand-1"),
    randomWeightsUnseeded("rand-2"),
    randomWeightsUnseeded("rand-3"),
    randomWeightsUnseeded("rand-4"),
    randomWeightsUnseeded("rand-5"),
  ];

  const weightVariants: { label: string; weights: bigint[] }[] = [
    {
      label: "equal",
      // equal across tiers 2..11
      weights: normalizeWeights([0n,0n, 1n,1n,1n,1n,1n,1n,1n,1n,1n,1n])
    },
    {
      label: "jackpot-heavy",
      // bias toward top tiers (8..11), heaviest on 11
      weights: normalizeWeights([0n,0n, 1n,1n,1n,2n,2n,3n,4n,5n,6n,10n])
    },
    {
      label: "mid-heavy",
      // bias mid tiers (5..8)
      weights: normalizeWeights([0n,0n, 1n,1n,2n,4n,5n,4n,3n,2n,1n,1n])
    },
    ...randomVariants
  ];

  const scenarios: Scenario[] = cartesian<any>(
    [ether(0.0), ether(0.1), ether(0.2)],               // reserveRatio
    [ether(0.2), ether(0.3)],                           // lpEdgeTarget
    [usdc(0.5), usdc(1), usdc(1.5)],                    // minimumPayout
    weightVariants                                       // premium weights variants
  ).map(([reserveRatio, lpEdgeTarget, minimumPayout, wv]) => ({ reserveRatio, lpEdgeTarget, minimumPayout, premiumTierWeights: wv.weights, weightsLabel: wv.label }));

  for (const s of scenarios) {
    it(scenarioName(s), async () => {
      await runScenario(s);
    });
  }
});

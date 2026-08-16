# Megapot audit details
- Total Prize Pool: $30,000 in USDC
    - HM awards: up to $25,920 in USDC 
        - If no valid Highs or Mediums are found, the HM pool is $0 
    - QA awards: $1,080 in USDC
    - Judge awards: $2,500 in USDC 
    - Scout awards: $500 USDC 
- [Read our guidelines for more details](https://docs.code4rena.com/competitions)
- Starts November 3, 2025 20:00 UTC 
- Ends November 13, 2025 20:00 UTC

### ❗ Important notes for wardens
1. A coded, runnable PoC is required for all High/Medium submissions to this audit. 
    - This repo includes a basic template to run the test suite.
    - PoCs must use the test suite provided in this repo.
    - Your submission will be marked as Insufficient if the POC is not runnable and working with the provided test suite.
    - Exception: PoC is optional (though recommended) for wardens with signal ≥ 0.68.
1. Judging phase risk adjustments (upgrades/downgrades):
    - High- or Medium-risk submissions downgraded by the judge to Low-risk (QA) will be ineligible for awards.
    - Upgrading a Low-risk finding from a QA report to a Medium- or High-risk finding is not supported.
    - As such, wardens are encouraged to select the appropriate risk level carefully during the submission phase.

## V12 findings

[V12](https://v12.zellic.io/) is [Zellic](https://zellic.io)'s in-house AI auditing tool. It is the only autonomous Solidity auditor that [reliably finds Highs and Criticals](https://www.zellic.io/blog/introducing-v12/). All issues found by V12 will be judged as out of scope and ineligible for awards.

[V12 findings can be viewed here](https://github.com/code-423n4/2025-11-megapot/blob/main/2025-11-megapot_V12.md).

## Publicly known issues

_Anything included in this section is considered a publicly known issue and is therefore ineligible for awards._

### Arithmetic Rounding

Accumulator and payout math truncates in favor of solvency; small “dust” is expected and acceptable.

### Emergency

Emergency refunds don’t claw back past referral fees; this is a policy decision. Refunded users with referrals receive ticketPrice minus referral portion.

The emergency mode is not intended to be recoverable - it is meant to be enabled in the case where the Jackpot gets stuck and can no longer progress.

### Referral Fallback

If no referral scheme is passed for a ticket then referral fees accrue to the LP pool.

# Overview

MegaPot V2 is a decentralized jackpot protocol where users purchase NFT-based jackpot tickets and liquidity providers fund prize pools. The system uses Pyth Network entropy for provably fair drawings, automatically distributes winnings based on number matches, and includes cross-chain bridge functionality.

## Links

- **Previous audits:** [Zellic Audit Report](https://github.com/code-423n4/2025-11-megapot/blob/main/Megapot%20v2%20-%20Zellic%20Audit%20Report.pdf)
- **Documentation:** https://github.com/code-423n4/2025-11-megapot/blob/main/DOCUMENTATION.md
- **Website:** https://megapot.io/
- **X/Twitter:** https://x.com/megapot

---

# Scope

### Files in scope

> Note: The nSLoC counts in the following table have been automatically generated and may differ depending on the definition of what a "significant" line of code represents. As such, they should be considered indicative rather than absolute representations of the lines involved in each contract.

| File   | nSLOC |
| ------ | --------------- |
| [contracts/lib/Combinations.sol](https://github.com/code-423n4/2025-11-megapot/blob/main/contracts/lib/Combinations.sol)  | 46 |
| [contracts/lib/FisherYatesWithRejection.sol](https://github.com/code-423n4/2025-11-megapot/blob/main/contracts/lib/FisherYatesWithRejection.sol) |  31 |
| [contracts/lib/JackpotErrors.sol](https://github.com/code-423n4/2025-11-megapot/blob/main/contracts/lib/JackpotErrors.sol) | 56 |
| [contracts/lib/TicketComboTracker.sol](https://github.com/code-423n4/2025-11-megapot/blob/main/contracts/lib/TicketComboTracker.sol) | 122 |
| [contracts/lib/UintCasts.sol](https://github.com/code-423n4/2025-11-megapot/blob/main/contracts/lib/UintCasts.sol) | 17 | 
| [contracts/GuaranteedMinimumPayoutCalculator.sol](https://github.com/code-423n4/2025-11-megapot/blob/main/contracts/GuaranteedMinimumPayoutCalculator.sol) | 138 | 
| [contracts/Jackpot.sol](https://github.com/code-423n4/2025-11-megapot/blob/main/contracts/Jackpot.sol) | 715 | 
| [contracts/JackpotBridgeManager.sol](https://github.com/code-423n4/2025-11-megapot/blob/main/contracts/JackpotBridgeManager.sol) | 138 |
| [contracts/JackpotLPManager.sol](https://github.com/code-423n4/2025-11-megapot/blob/main/contracts/JackpotLPManager.sol) | 188 | 
| [contracts/JackpotTicketNFT.sol](https://github.com/code-423n4/2025-11-megapot/blob/main/contracts/JackpotTicketNFT.sol) | 92 |
| [contracts/ScaledEntropyProvider.sol](https://github.com/code-423n4/2025-11-megapot/blob/main/contracts/ScaledEntropyProvider.sol) | 125 | 
| [contracts/interfaces/IJackpot.sol](https://github.com/code-423n4/2025-11-megapot/blob/main/contracts/interfaces/IJackpot.sol) |  7 | 
| [contracts/interfaces/IJackpotLPManager.sol](https://github.com/code-423n4/2025-11-megapot/blob/main/contracts/interfaces/IJackpotLPManager.sol) |  8 |
| [contracts/interfaces/IJackpotTicketNFT.sol](https://github.com/code-423n4/2025-11-megapot/blob/main/contracts/interfaces/IJackpotTicketNFT.sol) |  14 |
| [contracts/interfaces/IPayoutCalculator.sol](https://github.com/code-423n4/2025-11-megapot/blob/main/contracts/interfaces/IPayoutCalculator.sol) |  3 | 
| [contracts/interfaces/IScaledEntropyProvider.sol](https://github.com/code-423n4/2025-11-megapot/blob/main/contracts/interfaces/IScaledEntropyProvider.sol) |  9 | 
| **Totals** |  **1709** |

*For a machine-readable version, see [scope.txt](https://github.com/code-423n4/2025-11-megapot/blob/main/scope.txt)*

### Files out of scope

| File         |
| ------------ |
| [contracts/mocks/\*\*.\*\*](https://github.com/code-423n4/2025-11-megapot/tree/main/contracts/mocks) |
| Totals: 11 |

*For a machine-readable version, see [out_of_scope.txt](https://github.com/code-423n4/2025-11-megapot/blob/main/out_of_scope.txt)*

# Additional context

## Areas of concern (where to focus for bugs)
1) Is there any way to drain funds in the jackpot via LP or referrer deposit/withdraw flows?
2) Is there any way to drain the jackpot by falsifying tickets or gaming randomness?
3) Making sure the jackpot is truly fair and cannot be exploited (ie randomness is being correctly used and creating truly random outputs)
4) Is there any way that the jackpot could end up being -EV for LPs? Can we guarantee a minimum amount of edge?
5) Is there any way the jackpot could end up under-collateralized via accounting errors? Either business logic (ie. not accounting for all ticket winners, miscounting winners, misidentifying winners on claim) or rounding errors (especially accrued over time, rounding should be conservative with respect to collateralization)
6) Is there any way that LPs, referrers, or users could not be paid out what they're owed due to faulty state tracking or math? (ie not all ticket winners accounted for)
7) Is there any way to lock funds in the jackpot for any user - winners, referrers, LPs?
8) Is there any way that the jackpot could potentially get stuck and be unable to progress to the next drawing?
9) Can EIP-712 signatures be exploited as part of the bridging manager to either "steal" someones tickets or otherwise interfere with accounting? Either from signature replays or attempting hash collision.
10) is the case where the guaranteed payouts + premium tier minimum exceed the total value of the prize pool adequately handled?
11) Is all the bitpacking logic sound? Are there any potential boundary errors that could arise either between the lower bits where the normals are or the higher bits where powerball must be less than 255 - normalBall Max?
12) Can admin changes (e.g., ticketPrice, normalBallMax, fees) made mid-drawing create inconsistent states or violate expectations for players/LPs? Can global state changes affect the outcome of prior drawings (ie using a global param in calculations concerning a prior drawing)?

## Main invariants

### Payouts & Solvency

  - Total user payouts per drawing ≤ prizePool (never over-
  allocates).
  - Minimum payouts gating: if (minimumPayoutAllocation +
  premiumFloor) > prizePool, guaranteed minimums are skipped;
  otherwise minimums are paid and the remainder is allocated by
  weights.
  - Premium tier weights sum to 1e18; all payouts denominated in USDC (6
  decimals) with truncation favoring solvency.
  - Duplicate winners are proportionally reduce the premium payouts within a tier
  - Sum of all LP deposits (active and inactive), claimed winnings, and current drawing ticket    purchases must be less than total USDC balance of the contract (we expect some rounding that leaves dust unaccounted for)

### Tickets & Tiering

  - Normals are length 5, unique, in [1..normalBallMax]; bonusball
  in [1..bonusMax].
  - Bitpacking: normals occupy bits [1..normalBallMax]; bonusball at
  (normalBallMax + bonusball).
  - Tier formula: tierId = 2*(matchedNormals) + (bonusballMatch ?
  1 : 0), range [0..11].
  - Tickets are single-claim: burn before payout; no double-claim
  possible.

### LP & Accumulator

  - Accumulator strictly > 0 for all settled drawings.
  - Share/USDC conversions use the correct historical accumulator
  for the drawing of deposit/withdrawal.
  - Pool cap respect: deposits cannot exceed (lpPoolTotal +
  pendingDeposits); cannot set cap below current total + pending
  deposits.
  - Pending deposits are valued in USDC (this round); pending
  withdrawals are shares (finalized at settlement).

### Referrals & Fees

  - Referral splits sum exactly to PRECISE_UNIT; zero addresses and
  zero splits rejected.
  - Referrer share on winnings is deducted from user payout; if no
  scheme, referrer share is added to LP earnings.
  - Protocol fee applies only when (lpEarnings − userWinnings) >
  threshold; fee = (excess − threshold) * rate.

### Entropy & Draw Lifecycle

  - runJackpot only after drawingTime and when unlocked; locks
  drawing before request.
  - Entropy callback only from the configured provider and only when
  locked; completes settlement and initializes next drawing.
  - Entropy fee uses base + variable gas per powerball;
  getEntropyCallbackFee matches fee input to runJackpot.

### Access Control & Safety

  - Critical paths are nonReentrant; token transfers use SafeERC20.
  - Emergency mode gates refunds and emergency LP withdrawals;
  normal operations disabled while active.
  - Admin parameter changes apply to future drawings (not mid-
  drawing retroactive changes).

## All trusted roles in the protocol

| Role                                | Description                       |
| --------------------------------------- | ---------------------------- |
| Owner                          | Can update various jackpot settings                |

# Running Tests

## Prerequisites

The codebase relies on several `npm` dependencies as well as the `yarn` package manager to execute compilations through `hardhat`. All instructions have been tested under the following configuration:

- Node.js: `20.9.0`
- Yarn: `1.22.22`

## Dependencies

All dependencies of the project can be installed through `yarn`:

```bash
yarn install
```

Afterward, the example `.env.example` environment should be copied and have an actual `PRIVATE_KEY` entry added:

```bash 
cp .env.example .env
# .env should be edited to have an actual PRIVATE_KEY entry
```

## Compilation

The codebase can be compiled by issuing the `build` command to `yarn`:

```bash
yarn build
```

## Tests

Tests can be executed through the `test:clean` command as follows:

```bash!
yarn test:clean
```

## PoC

A dedicated `C4PoC.spec.ts` test file exists in the `test/poc` subfolder of the codebase with a single test suite that can be executed with the following command:

```
yarn test:poc
```

**For any submission to be accepted as valid by wardens who must provide a PoC, the test must execute successfully and must not mock any contract-initiated calls.** 

The imports and setups performed in the script can be freely adjusted as needed.

## Miscellaneous

Employees of Megapot and Coordination Labs and employees' family members are ineligible to participate in this audit.

Code4rena's rules cannot be overridden by the contents of this README. In case of doubt, please check with C4 staff.




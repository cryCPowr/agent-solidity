import { PRECISE_UNIT } from "./constants";
import { ethers, TypedDataEncoder } from "ethers";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { Address, Ticket, TierInfo, RelayTxData } from "./types";

export const calculateLpPoolCap = (
    normalBallMax: bigint,
    ticketPrice: bigint,
    lpEdgeTarget: bigint,
    reserveRatio: bigint
): bigint => {
    const maxAllowableTickets: bigint = BigInt(choose(Number(normalBallMax), 5) * (255 - Number(normalBallMax)));
    const maxPrizePool: bigint = maxAllowableTickets * ticketPrice * (PRECISE_UNIT - lpEdgeTarget) / PRECISE_UNIT;
    return maxPrizePool * PRECISE_UNIT / (PRECISE_UNIT - reserveRatio);
}

// For combinatorial calculations, we'll implement the combination formula
// C(n,k) = n! / (k! * (n-k)!)
// We can optimize this to avoid large factorials by using the iterative approach
const choose = (n: number, k: number): number => {
    if (k > n) return 0;
    if (k === 0 || k === n) return 1;
    
    k = Math.min(k, n - k); // Take advantage of symmetry
    let result = 1;
    
    for (let i = 0; i < k; i++) {
        result = result * (n - i) / (i + 1);
    }
    
    return Math.floor(result);
};

export const calculateReferralSchemeId = (referrers: Address[], referralSplitBps: bigint[]): string => {
    return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address[]", "uint256[]"], [referrers, referralSplitBps]));
};

export const calculatePackedTicket = (ticket: Ticket, maxNormalBall: bigint): bigint => {
    let bitVector = 0n;
    
    for (const num of ticket.normals) {
        if (num < 0 || num > 255) {
        throw new Error(`Invalid number ${num}: must be between 0 and 255`);
        }
    
        const mask = 1n << BigInt(num);
    
        // Check for duplicates (bit already set)
        if ((bitVector & mask) !== 0n) {
        throw new Error(`Duplicate number in set: ${num}`);
        }
    
        // Add this number to the set
        bitVector |= mask;
    }

    // Add bonusball to the bit vector
    bitVector |= 1n << BigInt(maxNormalBall + ticket.bonusball);
    
    return bitVector;
};

export const unpackTicket = (packedTicket: bigint, maxNormalBall: bigint): Ticket => {
    const balls: bigint[] = [];
    
    // Extract normal numbers (0 to maxNormalBall-1)
    for (let i = 0; i < 256; i++) {
        const mask = 1n << BigInt(i);
        if ((packedTicket & mask) !== 0n) {
            balls.push(BigInt(i));
        }
    }
    
    return {
        normals: balls.slice(0, -1),
        bonusball: balls[balls.length - 1] - maxNormalBall
    };
};

export const calculateTicketId = (drawingId: number, ticketIndex: number, packedTicket: bigint): bigint => {
    return BigInt(ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256", "uint256"], [drawingId, ticketIndex, packedTicket])));
};

export const calculateBonusballMax = (
    prizePool: bigint,
    normalBallMax: bigint,
    ticketPrice: bigint,
    lpEdgeTarget: bigint,
    bonusballMin: bigint
) => {
    const combosPerBonusball = BigInt(choose(Number(normalBallMax), 5));
    const minNumberTickets = prizePool * PRECISE_UNIT / ((PRECISE_UNIT - lpEdgeTarget) * ticketPrice);
    return BigInt(Math.max(Number(bonusballMin), Math.ceil(Number(minNumberTickets) / Number(combosPerBonusball))));
}

export const generateClaimWinningsSignature = (
    bridgeManagerAddress: Address,
    userTicketIds: bigint[],
    bridgeDetails: RelayTxData,
    signer: HardhatEthersSigner,
    chainId: number = 31337
) => {
    const domain = {
        name: "MegapotBridgeManager",
        version: "1.0.0",
        chainId: chainId,
        verifyingContract: bridgeManagerAddress
    };

    const types = {
        ClaimWinningsData: [
            { name: "ticketIds", type: "uint256[]" },
            { name: "bridgeDetails", type: "RelayTxData" }
        ],
        RelayTxData: [
            { name: "approveTo", type: "address" },
            { name: "to", type: "address" },
            { name: "data", type: "bytes" }
        ]
    }
    const value = {
        ticketIds: userTicketIds,
        bridgeDetails: {
            approveTo: bridgeDetails.approveTo,
            to: bridgeDetails.to,
            data: bridgeDetails.data
        }
    }

    return signer.signTypedData(
        domain,
        types,
        value
    );
};

export const generateClaimTicketSignature = (
    bridgeManagerAddress: Address,
    ticketIds: bigint[],
    recipient: Address,
    signer: HardhatEthersSigner,
    chainId: number = 31337
) => {
    const domain = {
        name: "MegapotBridgeManager",
        version: "1.0.0",
        chainId: chainId,
        verifyingContract: bridgeManagerAddress
    };

    const types = {
        ClaimTicketData: [
            { name: "ticketIds", type: "uint256[]" },
            { name: "recipient", type: "address" }
        ]
    }
    const value = {
        ticketIds: ticketIds,
        recipient: recipient
    }

    return signer.signTypedData(
        domain,
        types,
        value
    );
};

// Calculate total winners for a tier (expected + duplicates)
export const calculateTierTotalWinners = (
    tierIndex: number,
    normalMax: bigint,
    bonusballMax: bigint,
    duplicates: bigint
): bigint => {
    const matches = Math.floor(tierIndex / 2);
    const bonusballMatch = tierIndex % 2 === 1;
    const expectedWinners = calculateExpectedWinners(matches, normalMax, bonusballMax, bonusballMatch);
    return BigInt(expectedWinners) + duplicates;
};

// Calculate total minimum payout obligations across all tiers
export const calculateMinimumPayoutAllocation = (
    normalMax: bigint,
    bonusballMax: bigint,
    duplicates: bigint[],
    minimumPayout: bigint,
    minPayoutTiers: boolean[]
): bigint => {
    let totalMinimumAllocation = 0n;
    
    for (let i = 0; i < 12; i++) {
        if (minPayoutTiers[i]) {
            const tierWinners = calculateTierTotalWinners(i, normalMax, bonusballMax, duplicates[i]);
            totalMinimumAllocation += tierWinners * minimumPayout;
        }
    }
    
    return totalMinimumAllocation;
};

// Calculate premium tier payout for a specific tier
export const calculatePremiumTierPayout = (
    tierIndex: number,
    remainingPrizePool: bigint,
    premiumTierWeight: bigint,
    tierWinners: bigint
): bigint => {
    if (tierWinners === 0n) return 0n;
    return (remainingPrizePool * premiumTierWeight) / (PRECISE_UNIT * tierWinners);
};

// Calculate final tier payout (minimum + premium)
export const calculateFinalTierPayout = (
    tierIndex: number,
    remainingPrizePool: bigint,
    premiumTierWeight: bigint,
    tierWinners: bigint,
    minimumPayout: bigint,
    minPayoutTiers: boolean[]
): bigint => {
    const premiumAmount = calculatePremiumTierPayout(tierIndex, remainingPrizePool, premiumTierWeight, tierWinners);
    return minPayoutTiers[tierIndex] ? minimumPayout + premiumAmount : premiumAmount;
};

// Calculate total drawing payout (mirrors calculateAndStoreDrawingUserWinnings)
export const calculateTotalDrawingPayout = (
    prizePool: bigint,
    normalMax: bigint,
    bonusballMax: bigint,
    actualWinners: bigint[], // result array from trie
    duplicates: bigint[], // dupResult array from trie
    minimumPayout: bigint,
    minPayoutTiers: boolean[],
    premiumTierWeights: bigint[]
): { totalPayout: bigint; tierPayouts: bigint[] } => {
    // Calculate minimum payout allocation
    const minimumAllocation = calculateMinimumPayoutAllocation(
        normalMax, 
        bonusballMax, 
        duplicates, 
        minimumPayout, 
        minPayoutTiers
    );

    const remainingPrizePool = prizePool - minimumAllocation;
    const tierPayouts: bigint[] = new Array(12).fill(0n);
    let totalPayout = 0n;
    
    for (let i = 0; i < 12; i++) {
        const tierWinners = calculateTierTotalWinners(i, normalMax, bonusballMax, duplicates[i]);

        if (tierWinners > 0n) {
            const finalPayout = calculateFinalTierPayout(
                i,
                remainingPrizePool,
                premiumTierWeights[i],
                tierWinners,
                minimumPayout,
                minPayoutTiers
            );
            tierPayouts[i] = finalPayout;
            totalPayout += finalPayout * (actualWinners[i] + duplicates[i]);
        }
    }
    
    return { totalPayout, tierPayouts };
};

export const calculateExpectedWinners = (
    matches: number,
    normalMax: bigint,
    bonusballMax: bigint,
    bonusballMatch: boolean
) => {
    if (bonusballMatch) {
        return choose(5, matches) * choose(Number(normalMax) - 5, 5 - matches);
    } else {
        return choose(5, matches) * choose(Number(normalMax) - 5, 5 - matches) * (Number(bonusballMax) - 1);
    }
}

export const generateSubset = (set: bigint[]): bigint => {
    let subset = 0n;
    for (const num of set) {
        subset |= 1n << BigInt(num);
    }
    return subset;
}
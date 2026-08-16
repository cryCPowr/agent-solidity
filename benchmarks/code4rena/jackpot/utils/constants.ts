import { ethers } from "ethers";

export const ADDRESS_ZERO = ethers.ZeroAddress;
export const ZERO: bigint = BigInt(0);
export const ONE: bigint = BigInt(1);
export const ONE_DAY_IN_SECONDS: bigint = BigInt(86400);
export const THREE_MINUTES_IN_SECONDS: bigint = BigInt(180);
export const ZERO_BYTES32 = ethers.ZeroHash;

export const PRECISE_UNIT: bigint = BigInt(1e18);
export const BASIS_POINTS: bigint = BigInt(1e4);
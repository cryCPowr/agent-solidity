import { ethers } from "hardhat";

export const ether = (amount: number | string): bigint => {
  const weiString = ethers.parseEther(amount.toString());
  return BigInt(weiString);
};

export const usdc = (amount: number): bigint => {
  const weiString = 1000000 * amount;
  return BigInt(weiString);
};

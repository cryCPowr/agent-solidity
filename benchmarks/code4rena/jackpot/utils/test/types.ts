import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import { Address } from "@utils/types";

export type Account = {
  address: Address;
  wallet: HardhatEthersSigner;
};
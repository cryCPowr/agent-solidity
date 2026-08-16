import { ZERO } from "@utils/constants";
import { JsonRpcProvider } from "ethers";
import { time } from "@nomicfoundation/hardhat-toolbox/network-helpers";

export class Blockchain {
  public _provider: JsonRpcProvider;
  private _snapshotId: number;

  constructor(_provider: JsonRpcProvider) {
    this._provider = _provider;

    this._snapshotId = 0;
  }

  public async saveSnapshotAsync(): Promise<string> {
    const response = await this.sendJSONRpcRequestAsync("evm_snapshot", []);

    this._snapshotId = response;
    return response;
  }

  public async revertAsync(): Promise<void> {
    await this.sendJSONRpcRequestAsync("evm_revert", [this._snapshotId]);
  }

  public async revertByIdAsync(id: string): Promise<void> {
    await this.sendJSONRpcRequestAsync("evm_revert", [id]);
  }

  public async resetAsync(): Promise<void> {
    await this.sendJSONRpcRequestAsync("evm_revert", ["0x1"]);
  }

  public async getChainId(): Promise<number> {
    return Number((await this._provider.getNetwork()).chainId);
  }

  public async increaseTimeAsync(duration: bigint): Promise<any> {
    const currentTimestamp = await this.getCurrentTimestamp();
    await time.increaseTo(currentTimestamp + duration);
  }

  public async getCurrentTimestamp(): Promise<bigint> {
    const block = await this._provider.getBlock(await this._provider.getBlockNumber());
    return block ? BigInt(block.timestamp) : ZERO;
  }

  public async setNextBlockTimestamp(timestamp: number): Promise<any> {
    await this.sendJSONRpcRequestAsync("evm_setNextBlockTimestamp", [timestamp]);
  }

  public async waitBlocksAsync(count: number) {
    for (let i = 0; i < count; i++) {
      await this.sendJSONRpcRequestAsync("evm_mine", []);
    }
  }

  public async getLatestBlockNumber(): Promise<bigint> {
    const block = await this._provider.getBlock("latest");
    return block ? BigInt(block.number) : ZERO;
  }

  private async sendJSONRpcRequestAsync(method: string, params: any[]): Promise<any> {
    return this._provider.send(method, params);
  }
}

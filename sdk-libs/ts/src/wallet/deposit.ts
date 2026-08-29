import { compileUnsignedTransaction } from "../flows/compile.js";
import type { ZolanaClient } from "../client/client.js";
import type {
  Address,
  AssetDeposit,
  Bytes32,
  DepositAsset,
  Instruction,
  RequestContext,
  Transaction,
} from "../interface/types.js";
import { depositInstruction } from "../interface/instructions/index.js";
import { initializePoseidon } from "../hasher/index.js";
import { randomBlinding } from "../keypair/bytes.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { ownerUtxoHash } from "../transaction/utxo.js";
import { SOL_MINT } from "../transaction/asset.js";

import { resolveDepositSettlement } from "../flows/settlement.js";

import { WalletError, wrapWalletError } from "./error.js";
import { resolveShieldedRecipient } from "./registry.js";

/** @internal */
export interface DepositParams {
  readonly recipient: ShieldedAddress;
  readonly asset: Address;
  readonly amount: bigint;
  readonly depositor?: Address;
  readonly splTokenAccount?: Address;
  readonly splTokenProgram?: Address | null;
  readonly memo?: Uint8Array;
}

/** @internal */
export class Deposit {
  readonly data: Omit<AssetDeposit, "asset">;
  readonly utxoHash: Bytes32;
  readonly asset: Address;
  readonly settlement: DepositAsset;

  constructor(
    input: Readonly<{
      data: Omit<AssetDeposit, "asset">;
      utxoHash: Bytes32;
      asset: Address;
      settlement: DepositAsset;
    }>,
  ) {
    this.data = Object.freeze({
      ...input.data,
      viewTag: new Uint8Array(input.data.viewTag) as Bytes32,
      recipientOwnerHash: new Uint8Array(input.data.recipientOwnerHash) as Bytes32,
      blinding: new Uint8Array(input.data.blinding) as Bytes32,
      ...(input.data.memo === undefined ? {} : { memo: new Uint8Array(input.data.memo) }),
    });
    this.utxoHash = new Uint8Array(input.utxoHash) as Bytes32;
    this.asset = input.asset;
    this.settlement = input.settlement;
  }

  instruction(tree: Address, sender: Address): Promise<Instruction> {
    return depositInstruction({
      tree,
      depositor: sender,
      deposits: [{ ...this.data, asset: this.settlement }],
    });
  }

  viewTag(): Bytes32 {
    return new Uint8Array(this.data.viewTag) as Bytes32;
  }
}

/** @internal */
export async function createDeposit(params: DepositParams): Promise<Deposit> {
  try {
    await initializePoseidon();
    if (params.amount <= 0n || params.amount > 0xffff_ffff_ffff_ffffn) {
      throw new WalletError("WALLET_INVALID_AMOUNT", {
        details: { amount: params.amount.toString() },
      });
    }
    const recipientOwnerHash = params.recipient.ownerHash();
    const blinding = randomBlinding();
    const data: Omit<AssetDeposit, "asset"> = {
      // Confidential rings key the owner tag off the signing key, and the
      // wallet sync reads it back that way. The viewing key is a different key.
      viewTag: params.recipient.confidentialViewTag(),
      recipientOwnerHash,
      blinding,
      amount: params.amount,
      ...(params.memo === undefined ? {} : { memo: new Uint8Array(params.memo) }),
    };
    // A SOL deposit needs no token accounts, so one supplied alongside it is
    // ignored rather than rejected.
    const settlement = await resolveDepositSettlement(
      {
        asset: params.asset,
        ...(params.depositor === undefined ? {} : { depositor: params.depositor }),
        ...(params.splTokenAccount === undefined
          ? {}
          : { splTokenAccount: params.splTokenAccount }),
        ...(params.splTokenProgram === undefined
          ? {}
          : { splTokenProgram: params.splTokenProgram }),
      },
      () =>
        new WalletError("WALLET_MISSING_SPL_TOKEN_ACCOUNT", {
          details: { mint: params.asset },
        }),
    );
    return new Deposit({
      data,
      utxoHash: ownerUtxoHash({
        owner: recipientOwnerHash,
        asset: params.asset,
        amount: params.amount,
        blinding,
      }),
      asset: params.asset,
      settlement,
    });
  } catch (cause) {
    throw wrapWalletError("WALLET_CREATE_DEPOSIT", cause);
  }
}

export interface DepositTransactionParams {
  readonly client: ZolanaClient;
  readonly feePayer: Address;
  readonly depositor?: Address;
  readonly tree?: Address;
  readonly recipient: Address | ShieldedAddress;
  readonly asset?: Address;
  readonly amount: bigint;
  readonly splTokenAccount?: Address;
  readonly splTokenProgram?: Address | null;
  readonly memo?: Uint8Array;
}

export async function buildDepositTransaction(
  input: DepositTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const recipient = await resolveShieldedRecipient(
      { rpc: input.client, recipient: input.recipient },
      (unregistered) =>
        new WalletError("WALLET_RECIPIENT_NOT_REGISTERED", {
          details: { recipient: unregistered },
        }),
      context,
    );
    const depositor = input.depositor ?? input.feePayer;
    const tree = input.tree ?? input.client.tree;
    const asset = input.asset ?? SOL_MINT;
    const deposit = await createDeposit({
      recipient,
      asset,
      amount: input.amount,
      depositor,
      ...(input.splTokenAccount === undefined ? {} : { splTokenAccount: input.splTokenAccount }),
      ...(input.splTokenProgram === undefined ? {} : { splTokenProgram: input.splTokenProgram }),
      ...(input.memo === undefined ? {} : { memo: input.memo }),
    });
    const lifetime = await input.client.getLatestBlockhash(context);
    return compileUnsignedTransaction({
      feePayer: input.feePayer,
      lifetime,
      instructions: [await deposit.instruction(tree, depositor)],
    });
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_DEPOSIT", cause);
  }
}
